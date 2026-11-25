#!/usr/bin/env node
// Vigie — command line for people and CI. Same engine as the MCP server.
//   vigie check [folder]                 check a project folder (default: current folder)
//   vigie check npm:lodash@4.17.20 …     check exact package versions
//   vigie mcp                            start the MCP server (stdio)
//   vigie hook                           run as an agent hook (JSON event on stdin)
import { stat } from 'node:fs/promises';
import { checkPackages, checkProject, formatReport, compactReport, highPriority, sourcesList } from '../src/analyse.mjs';
import { VERSION, prune } from '../src/cache.mjs';
import { resolveVersion } from '../src/resolve.mjs';
import { normalizeEcosystem } from '../src/providers/osv.mjs';

const HELP = `Vigie ${VERSION} — known vulnerabilities, cross-checked across public databases.

Usage
  vigie check [folder]                   Check a project folder and its sub-folders (default: current folder)
  vigie check <eco>:<name>@<version> …   Check package versions, e.g. npm:lodash@4.17.20 pypi:django@3.2.1
                                         Without @version, the version a plain install would bring is checked.
  vigie sources                          List the databases queried
  vigie setup <claude|gemini|cursor>     Connect Vigie to a coding agent in this project (MCP server, hook, rule)
                                         --user: for all your projects · --remove: undo it
  vigie mcp                              Start the MCP server (stdio) for a coding agent
  vigie hook                             Agent hook: reads the event on stdin, blocks dangerous installs

Options
  --json               Machine-readable output
  --fail-on <level>    high (default): exit 1 on exploited, malicious, critical or high findings
                       any: exit 1 on any finding · none: never exit 1
  --no-recursive       Do not read sub-folders
  --all                Show every affected package in full (default: the 25 most urgent)
  -h, --help · -v, --version

Exit codes: 0 nothing above the threshold · 1 findings · 2 the check could not be completed or bad usage
What leaves your machine: package names and versions, sent to the public databases. Never your code.`;

const SPEC = /^([A-Za-z.]+):(.+)$/;

function parseSpec(arg) {
  const m = arg.match(SPEC);
  const ecosystem = m && normalizeEcosystem(m[1]);
  if (!ecosystem) return null;
  const rest = m[2];
  const at = rest.lastIndexOf('@');
  return at > 0 ? { ecosystem, name: rest.slice(0, at), spec: rest.slice(at + 1) } : { ecosystem, name: rest, spec: '' };
}

export async function cli(argv, out = (s) => process.stdout.write(s + '\n'), err = (s) => process.stderr.write(s + '\n')) {
  const args = [];
  const opt = { json: false, failOn: 'high', recursive: true, full: false, user: false, remove: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') opt.json = true;
    else if (a === '--no-recursive') opt.recursive = false;
    else if (a === '--all') opt.full = true;
    else if (a === '--user') opt.user = true;
    else if (a === '--remove') opt.remove = true;
    else if (a === '--fail-on') opt.failOn = argv[++i];
    else if (a.startsWith('--fail-on=')) opt.failOn = a.slice(10);
    else if (a === '-h' || a === '--help') return out(HELP), 0;
    else if (a === '-v' || a === '--version') {
      const warning = (await import('../src/setup.mjs')).homeMismatch();
      if (warning) err(warning);
      return out(VERSION), 0;
    }
    else if (a.startsWith('-') && a.length > 1) return err(`Unknown option ${a}. Try: vigie --help`), 2;
    else args.push(a);
  }
  if (!['high', 'any', 'none'].includes(opt.failOn)) return err('--fail-on expects: high, any or none'), 2;
  const [command, ...rest] = args;
  if (!command || command === 'help') return out(HELP), command ? 0 : 2;
  if (command === 'sources') {
    out(opt.json ? JSON.stringify({ sources: sourcesList() }, null, 2) : sourcesList().map((s) => `- ${s.name} — ${s.covers} (${s.url})`).join('\n'));
    return 0;
  }
  if (command === 'setup') {
    const { setup, agents, homeMismatch, ROOT } = await import('../src/setup.mjs');
    if (!rest.length) return err(`Which agent? vigie setup <${agents().map((a) => a.split(' ')[0]).join('|')}> [--user] [--remove]`), 2;
    try {
      const r = await setup(rest[0], { dir: rest[1] || '.', user: opt.user, remove: opt.remove });
      out(`Vigie ${opt.remove ? 'removed from' : 'set up for'} ${r.label} (${opt.user ? 'all your projects' : 'this project'}):`);
      out(r.log.map((l) => `  ${l}`).join('\n') || '  nothing to change');
      if (r.next.length) out(`Now run:\n${r.next.map((c) => `  ${c}`).join('\n')}`);
      if (!opt.remove) out(`Vigie's code is in ${ROOT}\nRestart the agent so it loads the new configuration.`);
      if (!opt.remove && homeMismatch()) err(homeMismatch());
      return 0;
    } catch (e) {
      return err(String(e.message)), 2;
    }
  }
  if (command !== 'check') return err(`Unknown command "${command}". Try: vigie --help`), 2;

  prune();
  const targets = rest.length ? rest : ['.'];
  const specs = targets.map(parseSpec);
  let report;
  let text;
  let extra = {};
  if (specs.every(Boolean)) {
    const unresolved = [];
    const packages = [];
    for (const s of specs) {
      try {
        packages.push({ ecosystem: s.ecosystem, name: s.name, version: await resolveVersion(s.ecosystem, s.name, s.spec) });
      } catch (e) {
        unresolved.push({ input: { name: `${s.name}${s.spec ? `@${s.spec}` : ''}` }, reason: `version could not be determined (${String(e.message).slice(0, 100)})` });
      }
    }
    report = await checkPackages(packages);
    report.skipped.push(...unresolved);
    if (unresolved.length && report.verdict === 'clean') report.verdict = 'incomplete';
    text = formatReport(report, { full: opt.full });
  } else if (targets.length === 1 && !specs[0]) {
    const info = await stat(targets[0]).catch(() => null);
    if (!info?.isDirectory()) return err(`"${targets[0]}" is neither a folder nor a package written as <ecosystem>:<name>@<version> (e.g. npm:lodash@4.17.20).`), 2;
    const res = await checkProject(targets[0], { recursive: opt.recursive, full: opt.full });
    ({ report, text } = res);
    extra = { root: res.project.root, files: res.project.files, notes: res.project.notes };
  } else {
    return err('Give either one folder, or only packages written as <ecosystem>:<name>@<version>.'), 2;
  }

  out(opt.json ? JSON.stringify({ ...compactReport(report), ...extra, findings: report.findings, signals: report.signals, accepted: report.accepted, skipped: report.skipped }, null, 2) : text);
  if (report.verdict === 'incomplete') return 2;
  const failing = opt.failOn === 'none' ? 0 : opt.failOn === 'any' ? report.findings.length : highPriority(report).length;
  return failing ? 1 : 0;
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === 'mcp') return (await import('../src/server.mjs')).main();
  if (argv[0] === 'hook') return (await import('./vigie-hook.mjs')).main();
  try {
    process.exitCode = await cli(argv);
  } catch (e) {
    process.stderr.write(`Vigie could not run this check: ${String(e?.message || e)}\n`);
    process.exitCode = 2;
  }
}

import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
const isMain = (() => {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (isMain) main();
