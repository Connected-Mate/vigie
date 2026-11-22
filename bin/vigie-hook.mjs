#!/usr/bin/env node
// Vigie hook for coding agents (Claude Code hook format: JSON on stdin, exit 2 = block and tell the agent).
// - Before a shell command that installs packages: checks them, blocks if one is dangerous.
// - After an edit of a dependency file: checks the project, reports dangerous findings to the agent.
// Fails open when the databases are unreachable, unless VIGIE_STRICT=1.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import { checkPackages, formatReport } from '../src/analyse.mjs';
import { readProject, MANIFESTS } from '../src/projet.mjs';
import { http } from '../src/cache.mjs';

const INSTALLERS = [
  { re: /^(?:npm|pnpm|bun)\s+(?:install|i|add)\b(.*)$/, ecosystem: 'npm' },
  { re: /^yarn\s+add\b(.*)$/, ecosystem: 'npm' },
  { re: /^(?:uv\s+)?(?:pip|pip3|python3?\s+-m\s+pip)\s+install\b(.*)$/, ecosystem: 'PyPI' },
  { re: /^(?:uv|poetry)\s+add\b(.*)$/, ecosystem: 'PyPI' },
];

/** Extracts [{ecosystem,name,version|null}] from a shell command line. */
export function parseInstalls(command) {
  const found = [];
  for (const part of String(command || '').split(/&&|\|\||;|\n|\|/)) {
    const cmd = part.trim().replace(/^(?:sudo\s+|npx\s+|[A-Z_]+=\S+\s+)+/, '');
    for (const { re, ecosystem } of INSTALLERS) {
      const m = cmd.match(re);
      if (!m) continue;
      for (const tok of m[1].trim().split(/\s+/)) {
        const t = tok.replace(/^["']|["']$/g, '');
        if (!t || t.startsWith('-') || /^(\.|\/|~|https?:|git[+@:]|file:)/.test(t) || /\.(tgz|whl|txt|gz|zip)$/.test(t)) continue;
        if (ecosystem === 'npm') {
          const mm = t.match(/^(@[\w.-]+\/[\w.-]+|[\w.-]+)(?:@(.+))?$/);
          if (mm) found.push({ ecosystem, name: mm[1], version: mm[2] && /^\d/.test(mm[2]) ? mm[2] : null });
        } else {
          const mm = t.match(/^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?(?:==([\w.!+-]+))?/);
          if (mm) found.push({ ecosystem, name: mm[1], version: mm[2] || null });
        }
      }
    }
  }
  return found;
}

async function latest(pkg) {
  if (pkg.ecosystem === 'npm') {
    const j = await http(`https://registry.npmjs.org/${pkg.name.replace('/', '%2F')}/latest`, { timeoutMs: 10000 });
    return j.version;
  }
  const j = await http(`https://pypi.org/pypi/${encodeURIComponent(pkg.name)}/json`, { timeoutMs: 10000 });
  return j.info.version;
}

const dangerous = (report) => report.findings.filter((f) => f.priority <= 1);

export async function run(event) {
  const tool = event?.tool_name;
  const input = event?.tool_input || {};
  let report;
  let context;

  if (tool === 'Bash') {
    const installs = parseInstalls(input.command);
    if (!installs.length) return { code: 0 };
    const resolved = [];
    for (const p of installs) {
      try {
        resolved.push({ ...p, version: p.version || (await latest(p)) });
      } catch {
        /* unknown package or registry down: the installer itself will complain */
      }
    }
    if (!resolved.length) return { code: 0 };
    report = await checkPackages(resolved);
    context = 'Vigie blocked this install';
  } else if (['Edit', 'Write', 'MultiEdit'].includes(tool) && MANIFESTS.includes(path.basename(String(input.file_path || '')))) {
    const project = await readProject(path.dirname(input.file_path));
    if (!project.packages.length) return { code: 0 };
    report = await checkPackages(project.packages);
    context = 'Vigie found dangerous dependencies after this edit';
  } else {
    return { code: 0 };
  }

  if (report.verdict === 'incomplete') {
    const msg = `Vigie could not check the dependencies (databases unreachable). ${process.env.VIGIE_STRICT === '1' ? 'Strict mode: blocked.' : 'Not blocking; check again later.'}`;
    return { code: process.env.VIGIE_STRICT === '1' ? 2 : 0, message: msg };
  }
  const bad = dangerous(report);
  if (!bad.length) return { code: 0 };
  return { code: 2, message: `${context}: ${bad.length} package(s) with a high-priority known vulnerability.\n\n${formatReport({ ...report, findings: bad }, { maxPackages: 10 })}\n\nFix these (use the "What to do" lines) or explain to the user why you cannot.` };
}

async function main() {
  let raw = '';
  for await (const chunk of process.stdin) raw += chunk;
  let event;
  try {
    event = JSON.parse(raw);
  } catch {
    process.exit(0);
  }
  try {
    const { code, message } = await run(event);
    if (message) process.stderr.write(message + '\n');
    process.exit(code);
  } catch (err) {
    process.stderr.write(`Vigie hook error: ${String(err.message || err)}\n`);
    process.exit(process.env.VIGIE_STRICT === '1' ? 2 : 0);
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
