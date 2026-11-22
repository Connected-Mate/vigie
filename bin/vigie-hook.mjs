#!/usr/bin/env node
// Vigie hook for coding agents. Reads one JSON event on stdin; exit 2 + a message on stderr = "stop, read this".
// - BEFORE a shell command that installs or runs a package: checks it and blocks if it is dangerous.
// - AFTER an install command or an edit of a dependency file: checks the project and tells the agent what to fix.
// Understands the event formats of Claude Code, Codex, Gemini CLI, Devin/Windsurf, Cursor and Copilot.
// Never hangs: a time budget cuts the check. When the databases cannot be reached it lets the command
// through and says so, unless VIGIE_STRICT=1.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { realpathSync, existsSync } from 'node:fs';
import { checkPackages, checkProject, formatReport, highPriority } from '../src/analyse.mjs';
import { isManifest, readIgnore } from '../src/projet.mjs';
import { setBudget, readState, writeState } from '../src/cache.mjs';
import { resolveVersion } from '../src/resolve.mjs';
import * as depsdev from '../src/providers/depsdev.mjs';

const strict = () => process.env.VIGIE_STRICT === '1';
const budgetMs = () => Math.min(Math.max(Number(process.env.VIGIE_HOOK_BUDGET_MS) || 20000, 2000), 120000);

// ---- reading a shell command ---------------------------------------------------------------------------------
/** Splits a command line into simple commands (lists of words), honouring quotes. */
export function splitCommands(line) {
  const commands = [];
  let words = [];
  let word = '';
  let has = false;
  let quote = null;
  const s = String(line ?? '');
  const endWord = () => {
    if (has) words.push(word);
    word = '';
    has = false;
  };
  const endCommand = () => {
    endWord();
    if (words.length) commands.push(words);
    words = [];
  };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === '\\' && quote === '"' && i + 1 < s.length) word += s[++i];
      else word += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      has = true;
    } else if (c === '\\' && i + 1 < s.length && /[\s"'\\$;|&()<>*?#]/.test(s[i + 1])) {
      if (s[i + 1] !== '\n') word += s[i + 1];
      has = true;
      i++;
    } else if (c === '\n' || c === ';' || c === '|' || c === '&' || c === '(' || c === ')' || c === '{' || c === '}') endCommand();
    else if (c === ' ' || c === '\t') endWord();
    else if (c === '#' && !has) {
      while (i < s.length && s[i] !== '\n') i++;
      endCommand();
    } else {
      word += c;
      has = true;
    }
  }
  endCommand();
  return commands;
}

const WRAPPERS = new Set(['sudo', 'command', 'exec', 'time', 'nice', 'nohup', 'env', 'then', 'do', 'else', 'if', 'corepack']);
const VALUE_FLAGS = {
  npm: ['--prefix', '-C', '--dir', '--registry', '-w', '--workspace', '--filter', '--tag', '--cache', '--userconfig', '--otp', '--cwd', '--loglevel'],
  PyPI: ['-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index-url', '--extra-index-url', '-t', '--target', '--prefix', '--root', '-f', '--find-links', '--python', '-p', '--platform', '--python-version', '--only-binary', '--no-binary', '--config-settings', '--upgrade-strategy', '--progress-bar', '--src', '--log', '--proxy', '--cert', '--trusted-host', '--group', '-G', '--optional', '--extra', '-E', '--source', '--index', '--package', '--script', '--marker', '--branch', '--rev', '--with', '--from', '--directory', '--project'],
  other: ['--manifest-path', '--features', '-F', '--registry', '--git', '--path', '--branch', '--tag', '--rev', '--rename', '--root', '--target', '-i', '--install-dir', '--bindir', '-s', '--source', '--framework', '-f', '--working-dir', '-d', '--package-directory', '-n'],
};
const NOT_A_PACKAGE = /^(\.|\/|~|[A-Za-z]:\\|https?:|git[+@:]|ssh:|file:|link:|workspace:|github:|\$)|[\\]|\.(tgz|whl|txt|gz|zip|toml|json|lock)$|^[a-z0-9_.-]+\/[a-z0-9_.-]+(#.*)?$/i;

const NOT_LOCAL = /^(\.|\/|~|[A-Za-z]:\\|https?:|git[+@:]|ssh:|file:|\$)/;

const npmSpec = (t) => {
  const m = t.match(/^(@[\w.-]+\/[\w.-]+|[\w.-]+)(?:@(.*))?$/);
  if (!m) return null;
  const alias = (m[2] || '').match(/^npm:(@[\w.-]+\/[\w.-]+|[\w.-]+)(?:@(.*))?$/); // name@npm:other@1 installs other
  return alias ? { name: alias[1], spec: alias[2] || '' } : { name: m[1], spec: m[2] || '' };
};
const pySpec = (t) => {
  const m = t.match(/^([A-Za-z0-9][\w.-]*?)(?:\[[^\]]*\])?\s*((?:===?|~=|!=|>=|<=|>|<|@).*)?$/);
  if (!m) return null;
  const spec = (m[2] || '').split(';')[0].trim();
  if (spec.startsWith('@')) {
    // poetry: name@1.2.3, name@^1.2, name@~1.2
    const p = spec.slice(1).trim().match(/^([\^~]?)(\d+)((?:\.\d+)*)$/);
    if (!p) return /^@\s*latest$/.test(spec) ? { name: m[1], spec: '' } : null;
    const v = p[2] + p[3];
    return { name: m[1], spec: p[1] === '^' ? `>=${v},<${Number(p[2]) + 1}` : p[1] === '~' ? `~=${p[3] ? v : `${v}.0`}` : `==${v}` };
  }
  return { name: m[1], spec };
};

/** What a simple command installs or runs: { ecosystem, items:[{name,spec}], run } or null. */
function readCommand(words, cwd) {
  let w = words.slice();
  while (w.length && (WRAPPERS.has(w[0]) || /^[A-Za-z_][A-Za-z0-9_]*=/.test(w[0]) || (w[0].startsWith('-') && w.length > 1))) w.shift();
  if (!w.length) return null;
  const bin = w[0].split(/[\\/]/).pop().replace(/\.(exe|cmd|bat|ps1)$/i, '');
  let rest = w.slice(1);
  let ecosystem;
  let run = false;
  let project = false; // the command also (re)installs the project's own dependency files
  const sub = () => rest.find((t) => !t.startsWith('-'));
  const after = (verb) => rest.slice(rest.indexOf(verb) + 1);

  if (bin === 'npx' || bin === 'bunx' || bin === 'pnpx') [ecosystem, run] = ['npm', true];
  else if (['npm', 'pnpm', 'yarn', 'bun'].includes(bin)) {
    ecosystem = 'npm';
    const verb = sub();
    if (['install', 'i', 'add', 'in', 'ins', 'isntall'].includes(verb) && !(bin === 'yarn' && verb !== 'add')) rest = after(verb);
    else if (bin === 'yarn' && verb === 'global' && after('global')[0] === 'add') rest = after('add');
    else if (['dlx', 'exec', 'x'].includes(verb) && (bin !== 'npm' || verb === 'exec')) [rest, run] = [after(verb), true];
    else {
      project = (verb === undefined && bin === 'yarn') || ['install', 'ci', 'update', 'up', 'upgrade', 'dedupe', 'audit', 'install-test', 'clean-install'].includes(verb);
      return project ? { ecosystem, items: [], project, dir: cwd } : null;
    }
    if (!rest.some((t) => !t.startsWith('-'))) project = true;
  } else if (/^pip(\d+(\.\d+)?)?$/.test(bin) || bin === 'pipx' || bin === 'uvx' || bin === 'uv' || bin === 'poetry' || /^python(\d+(\.\d+)?)?$/.test(bin) || bin === 'py') {
    ecosystem = 'PyPI';
    if (/^python|^py$/.test(bin)) {
      if (rest[0] !== '-m' || rest[1] !== 'pip') return null;
      rest = rest.slice(2);
    }
    if (bin === 'uv' && rest[0] === 'pip') rest = rest.slice(1);
    const verb = sub();
    if (bin === 'uvx') run = true;
    else if (bin === 'uv' && verb === 'tool' && ['run', 'install'].includes(after('tool')[0])) [rest, run] = [after('tool').slice(1), true];
    else if (bin === 'pipx' && ['run', 'install'].includes(verb)) [rest, run] = [after(verb), true];
    else if (verb === 'install' && bin !== 'uv' && bin !== 'poetry') rest = after(verb);
    else if (verb === 'install' && words.includes('pip')) rest = after(verb);
    else if (verb === 'add' && (bin === 'uv' || bin === 'poetry')) rest = after(verb);
    else {
      project = ['install', 'sync', 'lock', 'update', 'upgrade'].includes(verb);
      return project ? { ecosystem, items: [], project, dir: cwd } : null;
    }
    if (rest.some((t) => ['-r', '--requirement', '-e', '--editable'].includes(t) || /^(-r|--requirement=)/.test(t))) project = true;
  } else if (bin === 'cargo' && ['add', 'install'].includes(sub())) [ecosystem, rest] = ['crates.io', after(sub())];
  else if (bin === 'go' && ['get', 'install'].includes(sub())) [ecosystem, rest] = ['Go', after(sub())];
  else if (bin === 'gem' && sub() === 'install') [ecosystem, rest] = ['RubyGems', after('install')];
  else if (bin === 'bundle' && sub() === 'add') [ecosystem, rest] = ['RubyGems', after('add')];
  else if (bin === 'composer' && sub() === 'require') [ecosystem, rest] = ['Packagist', after('require')];
  else if (bin === 'dotnet' && sub() === 'add' && rest.includes('package')) [ecosystem, rest] = ['NuGet', after('package')];
  else if (['bash', 'sh', 'zsh', 'dash', 'fish'].includes(bin) && rest.some((t) => /^-[a-z]*c$/.test(t))) return { nested: rest[rest.findIndex((t) => /^-[a-z]*c$/.test(t)) + 1] ?? '' };
  else return bin === 'cd' && rest[0] ? { cd: rest[0] } : null;

  const valueFlags = new Set(VALUE_FLAGS[ecosystem === 'npm' || ecosystem === 'PyPI' ? ecosystem : 'other']);
  const items = [];
  let version = null;
  let inDir = null;
  const loose = ecosystem !== 'npm' && ecosystem !== 'PyPI';
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i];
    if (t === '--') continue;
    if (t.startsWith('-')) {
      const eq = t.includes('=');
      if (/^(-v|--version|--vers)$/.test(t) && ecosystem !== 'npm' && ecosystem !== 'PyPI') version = rest[++i];
      else if (/^(--version|--vers)=/.test(t)) version = t.split('=')[1];
      else if (run && /^(-p|--package|--from|--with|--spec)$/.test(t) && rest[i + 1]) {
        const s = ecosystem === 'npm' ? npmSpec(rest[++i]) : pySpec(rest[++i]);
        if (s) items.push({ ...s, explicit: true });
      } else if (!eq && valueFlags.has(t)) {
        if (['--prefix', '-C', '--dir', '--cwd', '--directory', '--project', '--working-dir', '-d'].includes(t) && rest[i + 1]) inDir = rest[i + 1];
        i++;
      } else if (/^(--prefix|--dir|--cwd|--directory|--project|--working-dir)=/.test(t)) inDir = t.slice(t.indexOf('=') + 1);
      continue;
    }
    if ((loose ? NOT_LOCAL.test(t) : NOT_A_PACKAGE.test(t)) && !(ecosystem === 'npm' && t.startsWith('@'))) {
      if (run) break;
      continue;
    }
    let item = null;
    if (ecosystem === 'npm') item = npmSpec(t);
    else if (ecosystem === 'PyPI') item = pySpec(t);
    else if (ecosystem === 'Packagist') {
      const m = t.match(/^([\w.-]+\/[\w.-]+)(?::(.+))?$/);
      if (m) item = { name: m[1], spec: m[2] || '' };
      else if (items.length && /^[\^~\d<>=]/.test(t)) items[items.length - 1].spec = t;
    } else if (ecosystem === 'Go') {
      const m = t.match(/^([\w.-]+\.[a-z]+\/[^@\s]+)(?:@(.+))?$/);
      if (m) item = { name: m[1].replace(/\/\.\.\.$/, ''), spec: (m[2] || '').replace(/^v(?=\d)/, '') };
    } else {
      const m = t.match(/^([A-Za-z0-9][\w.-]*)(?:@(.+))?$/);
      if (m) item = { name: m[1], spec: m[2] || '' };
    }
    if (item) items.push(item);
    if (run) break; // what follows the package is the program's own arguments
  }
  if (version && items.length) items[items.length - 1].spec = version.replace(/^v(?=\d)/, '');
  // `npx tsc` runs a program already installed in the project, not a download
  const where = inDir ? path.resolve(cwd, inDir) : cwd;
  let kept = items;
  if (run && items.some((it) => it.explicit)) kept = items.filter((it) => it.explicit); // `npx -p pkg cmd`: cmd comes from pkg
  else if (run && ecosystem === 'npm') kept = items.filter((it) => it.spec || !existsSync(path.join(where, 'node_modules', '.bin', it.name)));
  // an install with no package we can name (a path, an archive, a URL) still changes the project: check it afterwards
  return { ecosystem, items: kept.map(({ name, spec }) => ({ name, spec })), run, project: project || !run, dir: where };
}

/**
 * Reads a whole command line.
 * @returns { installs: [{ecosystem,name,spec,run}], project: bool, dir: folder the install runs in }
 */
export function parseCommand(command, cwd = process.cwd(), depth = 0) {
  const out = { installs: [], project: false, dir: cwd };
  let dir = cwd;
  for (const words of splitCommands(command)) {
    const r = readCommand(words, dir);
    if (!r) continue;
    if (r.cd) dir = path.resolve(dir, r.cd.replace(/^~(?=\/|$)/, process.env.HOME || '~'));
    else if (r.nested !== undefined) {
      if (depth < 2) {
        const inner = parseCommand(r.nested, dir, depth + 1);
        out.installs.push(...inner.installs);
        if (inner.project || inner.installs.length) Object.assign(out, { project: out.project || inner.project, dir: inner.dir });
      }
    } else {
      for (const it of r.items) out.installs.push({ ecosystem: r.ecosystem, name: it.name, spec: it.spec, run: Boolean(r.run) });
      if (r.project || r.items.length) {
        out.project = out.project || r.project || !r.run;
        out.dir = r.dir || dir;
      }
    }
  }
  return out;
}

/** Kept for readability in tests: [{ecosystem,name,version|null}] where version is only set when exact. */
export function parseInstalls(command) {
  return parseCommand(command).installs.map((p) => ({ ecosystem: p.ecosystem, name: p.name, version: /^(==)?\d[\w.+!-]*$/.test(p.spec) ? p.spec.replace(/^==/, '') : null }));
}

// ---- the event, whatever the agent ---------------------------------------------------------------------------
const SHELL_TOOLS = new Set(['bash', 'shell', 'run_shell_command', 'exec', 'run_command', 'execute_command', 'local_shell', 'terminal', 'run_terminal_cmd']);
const EDIT_TOOLS = new Set(['edit', 'write', 'multiedit', 'notebookedit', 'write_file', 'replace', 'create', 'str_replace', 'apply_patch', 'edit_file']);

export function readEvent(e) {
  if (!e || typeof e !== 'object') return null;
  const name = String(e.hook_event_name || e.hookEventName || e.agent_action_name || '').toLowerCase();
  const cwd = [e.cwd, e.tool_info?.cwd, Array.isArray(e.workspace_roots) && e.workspace_roots[0], process.env.CLAUDE_PROJECT_DIR, process.env.DEVIN_PROJECT_DIR].find((x) => typeof x === 'string' && x) || process.cwd();
  let input = e.tool_input ?? e.toolArgs ?? e.tool_info ?? {};
  if (typeof input === 'string') {
    try {
      input = JSON.parse(input);
    } catch {
      input = { command: input };
    }
  }
  const tool = String(e.tool_name || e.toolName || '').toLowerCase();
  const after = /^(post|after)/.test(name) || 'tool_response' in e || 'toolResult' in e;
  const command = typeof input?.command === 'string' ? input.command : typeof input?.command_line === 'string' ? input.command_line : typeof e.command === 'string' ? e.command : null;
  const file = [input?.file_path, input?.path, input?.filePath, e.file_path].find((x) => typeof x === 'string' && x);
  const session = String(e.session_id || e.sessionId || e.conversation_id || e.trajectory_id || '');
  if (command !== null && (SHELL_TOOLS.has(tool) || !tool)) return { kind: 'shell', after, command, cwd, session, claude: e.hook_event_name === 'PreToolUse' };
  if (file && (EDIT_TOOLS.has(tool) || /fileedit|write_code/.test(name))) return { kind: 'edit', after: true, file: path.resolve(cwd, file), cwd, session };
  return null;
}

// ---- checks ------------------------------------------------------------------------------------------------------
const unreachable = (what) => {
  const msg = `Vigie could not check ${what} (vulnerability databases unreachable or too slow). ${strict() ? 'Strict mode: blocked. Try again in a moment.' : 'Not blocked. Run the check again later (Vigie check_project) and tell the user this install was not verified.'}`;
  return { code: strict() ? 2 : 0, message: msg };
};
const RULE = 'Fix these (use the "What to do" lines) or stop and explain to the user why you cannot. Do not work around this check, and do not edit .vigieignore yourself: accepting a known risk is the user\'s decision.';

async function beforeInstall(ev, x) {
  const { installs, dir } = parseCommand(ev.command, ev.cwd);
  if (!installs.length) return { code: 0 };
  const unique = [...new Map(installs.map((p) => [`${p.ecosystem}|${p.name}|${p.spec}`, p])).values()].slice(0, 40);
  const named = [];
  const unknown = [];
  await Promise.all(unique.map(async (p) => {
    try {
      named.push({ ecosystem: p.ecosystem, name: p.name, version: await x.resolve(p.ecosystem, p.name, p.spec) });
    } catch (err) {
      // 404 = the registry does not know it: the installer itself will say so
      if (err.status !== 404) unknown.push(`${p.name}${p.spec ? `@${p.spec}` : ''}`);
    }
  }));
  if (!named.length) return unknown.length ? unreachable(unknown.join(', ')) : { code: 0 };

  // what each package pulls in (best effort: the project's real lockfile is checked after the install)
  const tree = [];
  await Promise.all(named.map(async (p) => {
    try {
      for (const d of await x.tree(p)) tree.push({ ...d, via: `${p.name}@${p.version}` });
    } catch { /* direct package only */ }
  }));
  const ignore = await readIgnore(dir);
  const report = await checkPackages([...named, ...tree.slice(0, 1500)], x.providers, { softTimeoutMs: 8000, ignore });
  if (report.verdict === 'incomplete') return unreachable(named.map((p) => `${p.name}@${p.version}`).join(', '));

  const direct = new Set(named.map((p) => `${p.ecosystem}|${p.name}|${p.version}`));
  const isDirect = (f) => direct.has(`${f.package.ecosystem}|${f.package.name}|${f.package.version}`);
  // direct package: exploited, malicious, critical or high. Pulled-in package: only exploited or malicious.
  const blocking = report.findings.filter((f) => (isDirect(f) ? f.priority <= 1 : f.priority === 0));
  if (blocking.length) {
    return {
      code: 2,
      message: `Vigie blocked this command: ${blocking.length} package(s) it would install have a high-priority known vulnerability.\n\n${formatReport({ ...report, findings: blocking, signals: [], skipped: [] }, { maxPackages: 10 })}\n\n${RULE}`,
    };
  }
  const notes = [];
  const indirect = highPriority(report).filter((f) => !isDirect(f));
  if (indirect.length) notes.push(`Vigie: this install pulls in ${indirect.length} package(s) with a high-severity known vulnerability (${indirect.slice(0, 6).map((f) => `${f.package.name}@${f.package.version}`).join(', ')}). Not blocked; run Vigie check_project after the install and fix what it reports.`);
  for (const s of report.signals.filter((x) => isDirect({ package: x.package }))) notes.push(`Vigie: ${s.package.name}@${s.package.version} — ${s.text}`);
  if (unknown.length) notes.push(`Vigie could not determine the version of ${unknown.join(', ')}: not verified.`);
  return { code: 0, context: notes.join('\n') };
}

async function afterChange(ev, dir, what, x) {
  const { report } = await checkProject(dir, { recursive: false, softTimeoutMs: 8000 }, x.providers);
  if (!report.checked) return { code: 0 };
  if (report.verdict === 'incomplete') return unreachable('the project dependencies');
  const bad = highPriority(report);
  // say each problem once per session: a known, already-reported finding must not interrupt every edit
  const stateKey = `hook:${ev.session || 'no-session'}:${dir}`;
  const already = new Set(ev.session ? (await readState(stateKey)) || [] : []);
  const idOf = (f) => `${f.package.ecosystem}|${f.package.name}|${f.package.version}|${f.vulnerabilities.map((v) => v.id).sort().join(',')}`;
  const fresh = bad.filter((f) => !already.has(idOf(f)));
  if (!fresh.length) return { code: 0 };
  if (ev.session) await writeState(stateKey, [...already, ...fresh.map(idOf)].slice(-2000));
  return {
    code: 2,
    message: `Vigie checked ${dir} after ${what}: ${fresh.length} package(s) with a high-priority known vulnerability.\n\n${formatReport({ ...report, findings: fresh, signals: [], skipped: [] }, { maxPackages: 10 })}\n\n${RULE}`,
  };
}

/** @param inject test seams: { resolve, tree, providers } */
export async function run(event, inject = {}) {
  const x = { resolve: resolveVersion, tree: depsdev.dependencies, providers: undefined, ...inject };
  const ev = readEvent(event);
  if (!ev) return { code: 0 };
  if (ev.kind === 'edit') return isManifest(path.basename(ev.file)) ? afterChange(ev, path.dirname(ev.file), `the edit of ${path.basename(ev.file)}`, x) : { code: 0 };
  if (!ev.after) return { ...(await beforeInstall(ev, x)), claude: ev.claude };
  const parsed = parseCommand(ev.command, ev.cwd);
  return parsed.project ? afterChange(ev, parsed.dir, 'this install', x) : { code: 0 };
}

async function readStdin(maxMs = 5000) {
  if (process.stdin.isTTY) return '';
  let raw = '';
  const timer = setTimeout(() => process.stdin.destroy(), maxMs);
  try {
    process.stdin.setEncoding('utf8');
    for await (const chunk of process.stdin) {
      raw += chunk;
      if (raw.length > 20 * 1024 * 1024) break;
    }
  } catch { /* closed early */ }
  clearTimeout(timer);
  return raw;
}

export async function main() {
  const raw = await readStdin();
  let event;
  try {
    event = JSON.parse(raw);
  } catch {
    process.exit(0); // not an event: never get in the way
  }
  const budget = budgetMs();
  setBudget(budget);
  // last resort: whatever happens, answer before the agent's own timeout
  const guard = setTimeout(() => {
    const r = unreachable('this change in time');
    process.stderr.write(r.message + '\n');
    process.exit(r.code);
  }, budget + 1500);
  try {
    const { code, message, context, claude } = await run(event);
    clearTimeout(guard);
    if (message) process.stderr.write(message + '\n');
    else if (context && claude) process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: context } }) + '\n');
    else if (context) process.stderr.write(context + '\n');
    process.exitCode = code;
  } catch (err) {
    clearTimeout(guard);
    process.stderr.write(`Vigie hook error: ${String(err?.message || err).slice(0, 300)}${strict() ? ' (strict mode: blocked)' : ' (not blocked)'}\n`);
    process.exitCode = strict() ? 2 : 0;
  }
}

const isMain = (() => {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (isMain) main();
