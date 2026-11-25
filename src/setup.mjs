// `vigie setup` — writes (or removes) the agent configuration, so nobody edits JSON by hand.
// It only ever touches Vigie's own entries, keeps everything else, and refuses to overwrite a file it cannot read.
import { readFile, writeFile, mkdir, rename, unlink, rmdir } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';

export const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const SERVER = path.join(ROOT, 'src', 'server.mjs');
const HOOK = path.join(ROOT, 'bin', 'vigie-hook.mjs');
const q = (p) => (/[\s"'$]/.test(p) ? `"${p.replace(/(["$\\])/g, '\\$1')}"` : p);
/**
 * A path as written in an agent's configuration. Windows paths get forward slashes: agents hand the command to cmd,
 * PowerShell or Git Bash depending on the machine, and a backslash does not survive all three (node accepts both).
 */
export const slashed = (p, sep = path.sep) => (sep === '\\' ? p.replaceAll('\\', '/') : p);
/** The same path, quoted when a command line needs it. */
export const shellPath = (p, sep = path.sep) => q(slashed(p, sep));
const hookCommand = () => `node ${shellPath(HOOK)}`;
const isOurs = (command) => /vigie-hook(\.mjs)?\b/.test(String(command || ''));

export const RULE = `## Vigie — known vulnerabilities
- Before adding or upgrading a dependency, call the Vigie tool \`check_packages\` with the exact version.
- Before saying a task is done, if dependency files changed, call Vigie \`check_project\` on the project folder.
- A "vulnerable" verdict must be fixed or explained to me. An "incomplete" verdict must be told to me: never present unchecked packages as safe.
- Never edit \`.vigieignore\` yourself: accepting a known risk is my decision.`;
const START = '<!-- vigie:start -->';
const END = '<!-- vigie:end -->';

async function readJson(file) {
  let text;
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') return null;
    throw err;
  }
  if (!text.trim()) return {};
  try {
    const j = JSON.parse(text.replace(/^﻿/, ''));
    if (!j || typeof j !== 'object' || Array.isArray(j)) throw new Error('not an object');
    return j;
  } catch {
    throw new Error(`${file} is not valid JSON: fix or move it first (Vigie will not overwrite it)`);
  }
}

async function writeAtomic(file, text) {
  await mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.vigie-tmp`;
  await writeFile(tmp, text);
  await rename(tmp, file);
}

/** Deletes a file, then its folder when that folder is an agent's own (.claude, .cursor…) and is now empty. */
async function dropFile(file) {
  await unlink(file);
  const folder = path.dirname(file);
  if (path.basename(folder).startsWith('.')) await rmdir(folder).catch(() => {});
}

// Every file is read and its new content worked out first; `plan` collects the writes, which run only once
// all the files could be read. A broken settings file therefore stops setup before anything is written.

/** Applies `change(json)` to a JSON file. Deletes the file (and its empty folder) when nothing is left. */
async function editJson(file, change, plan) {
  const before = await readJson(file);
  const json = structuredClone(before ?? {});
  change(json);
  const text = JSON.stringify(json, null, 2) + '\n';
  if (before !== null && JSON.stringify(before) === JSON.stringify(json)) return plan.push({ line: `unchanged  ${file}` });
  if (!Object.keys(json).length) {
    if (before === null) return;
    return plan.push({ line: `removed    ${file}`, run: () => dropFile(file) });
  }
  plan.push({ line: `${before === null ? 'created' : 'updated'}    ${file}`, run: () => writeAtomic(file, text) });
}

const prune = (obj, key) => {
  if (obj[key] && typeof obj[key] === 'object' && !Object.keys(obj[key]).length) delete obj[key];
};

const mcpEntry = (remove, extra = {}) => (json) => {
  json.mcpServers = json.mcpServers && typeof json.mcpServers === 'object' ? json.mcpServers : {};
  if (remove) delete json.mcpServers.vigie;
  else json.mcpServers.vigie = { ...extra, command: 'node', args: [slashed(SERVER)] };
  prune(json, 'mcpServers');
};

/** Claude Code / Gemini CLI style: hooks[event] = [{ matcher, hooks: [{ type, command, timeout }] }] */
const nestedHooks = (remove, wanted) => (json) => {
  json.hooks = json.hooks && typeof json.hooks === 'object' ? json.hooks : {};
  for (const event of Object.keys(json.hooks)) {
    if (!Array.isArray(json.hooks[event])) continue;
    json.hooks[event] = json.hooks[event]
      .map((group) => (Array.isArray(group?.hooks) ? { ...group, hooks: group.hooks.filter((h) => !isOurs(h?.command)) } : group))
      .filter((group) => !Array.isArray(group?.hooks) || group.hooks.length);
    if (!json.hooks[event].length) delete json.hooks[event];
  }
  if (!remove) for (const [event, group] of Object.entries(wanted)) json.hooks[event] = [...(json.hooks[event] || []), group];
  prune(json, 'hooks');
};

async function ruleBlock(file, remove, plan) {
  let text = '';
  try {
    text = await readFile(file, 'utf8');
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    if (remove) return;
  }
  const block = `${START}\n${RULE}\n${END}`;
  const has = text.includes(START) && text.includes(END);
  let stripped = text;
  if (has) {
    const parts = [text.slice(0, text.indexOf(START)).replace(/\n+$/, ''), text.slice(text.indexOf(END) + END.length).replace(/^\n+/, '').replace(/\n+$/, '')].filter(Boolean);
    stripped = parts.length ? `${parts.join('\n\n')}\n` : '';
  }
  const next = remove ? stripped : `${stripped.trim() ? stripped.replace(/\n*$/, '\n\n') : ''}${block}\n`;
  if (next === text) return plan.push({ line: `unchanged  ${file}` });
  if (!next.trim()) return plan.push({ line: `removed    ${file}`, run: () => dropFile(file) });
  plan.push({ line: `${text ? 'updated' : 'created'}    ${file}`, run: () => writeAtomic(file, next) });
}

const AGENTS = {
  claude: {
    label: 'Claude Code',
    async apply({ dir, home, user, remove, plan, next }) {
      const base = user ? path.join(home, '.claude') : path.join(dir, '.claude');
      const hook = (timeout) => ({ type: 'command', command: hookCommand(), timeout });
      await editJson(path.join(base, 'settings.json'), nestedHooks(remove, {
        PreToolUse: { matcher: 'Bash', hooks: [hook(30)] },
        PostToolUse: { matcher: 'Bash|Edit|Write|MultiEdit', hooks: [hook(30)] },
      }), plan);
      if (user) next.push(remove ? 'claude mcp remove --scope user vigie' : `claude mcp add --scope user vigie -- node ${shellPath(SERVER)}`);
      else await editJson(path.join(dir, '.mcp.json'), mcpEntry(remove), plan);
      await ruleBlock(user ? path.join(base, 'CLAUDE.md') : path.join(dir, 'CLAUDE.md'), remove, plan);
    },
  },
  gemini: {
    label: 'Gemini CLI',
    async apply({ dir, home, user, remove, plan }) {
      const base = user ? path.join(home, '.gemini') : path.join(dir, '.gemini');
      await editJson(path.join(base, 'settings.json'), (json) => {
        mcpEntry(remove)(json);
        nestedHooks(remove, { BeforeTool: { matcher: 'run_shell_command', hooks: [{ name: 'vigie', type: 'command', command: hookCommand(), timeout: 30000 }] } })(json);
      }, plan);
      await ruleBlock(user ? path.join(base, 'GEMINI.md') : path.join(dir, 'GEMINI.md'), remove, plan);
    },
  },
  cursor: {
    label: 'Cursor',
    async apply({ dir, home, user, remove, plan }) {
      const base = user ? path.join(home, '.cursor') : path.join(dir, '.cursor');
      await editJson(path.join(base, 'mcp.json'), mcpEntry(remove, { type: 'stdio' }), plan);
      await editJson(path.join(base, 'hooks.json'), (json) => {
        json.hooks = json.hooks && typeof json.hooks === 'object' ? json.hooks : {};
        const list = (Array.isArray(json.hooks.beforeShellExecution) ? json.hooks.beforeShellExecution : []).filter((h) => !isOurs(h?.command));
        if (!remove) list.push({ command: hookCommand(), timeout: 30 });
        if (list.length) json.hooks.beforeShellExecution = list;
        else delete json.hooks.beforeShellExecution;
        prune(json, 'hooks');
        if (json.hooks) json.version = json.version ?? 1;
        else if (Object.keys(json).length === 1 && json.version === 1) delete json.version;
      }, plan);
      if (!user) await ruleBlock(path.join(dir, 'AGENTS.md'), remove, plan);
    },
  },
};

export const agents = () => Object.entries(AGENTS).map(([id, a]) => `${id} (${a.label})`);

/**
 * @returns { log: [what changed], next: [commands still to run] }
 */
export async function setup(agent, { dir = process.cwd(), home = os.homedir(), user = false, remove = false } = {}) {
  const target = AGENTS[String(agent || '').toLowerCase()];
  if (!target) throw new Error(`Unknown agent "${agent ?? ''}". Choose one of: ${Object.keys(AGENTS).join(', ')}. Other agents: see AGENT-SETUP.md`);
  const plan = [];
  const next = [];
  await target.apply({ dir: path.resolve(dir), home, user, remove, plan, next });
  const log = [];
  for (const step of plan) {
    if (step.run) await step.run();
    log.push(step.line);
  }
  return { label: target.label, log, next };
}

const real = (p) => {
  try {
    return realpathSync(p);
  } catch {
    return path.resolve(p);
  }
};

/**
 * The person (or their company) can choose Vigie's folder with VIGIE_HOME. When this copy runs from another
 * folder, the choice was ignored: returns the sentence that says so, or '' when all is well.
 */
export function homeMismatch(env = process.env, root = ROOT) {
  const wanted = String(env.VIGIE_HOME || '').trim();
  if (!wanted || real(wanted) === real(root)) return '';
  return `Warning: VIGIE_HOME is set to ${wanted}, but this Vigie runs from ${root}. That folder was chosen for Vigie: install and run it from there (AGENT-SETUP.md, step 2), or unset VIGIE_HOME.`;
}
