#!/usr/bin/env node
// Vigie — MCP server (stdio, JSON-RPC 2.0, one JSON message per line). No dependency.
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import { checkPackages, checkProject, checkTechnologies, formatReport, formatTechnologies, sourcesList, providers } from './analyse.mjs';
import { VERSION, prune } from './cache.mjs';

const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

const INSTRUCTIONS = `Vigie checks known vulnerabilities across several public databases (OSV.dev, CISA KEV, EPSS, CERT-FR, deps.dev).
Rules for the agent:
1. BEFORE adding or upgrading any dependency, call check_packages with its exact version.
2. BEFORE declaring a task done in a project whose dependency files changed, call check_project on the project folder.
3. If the verdict is "vulnerable", apply the "What to do" lines (or tell the user why you cannot) before continuing.
4. If the verdict is "incomplete", say so to the user: never present unchecked packages as safe.
5. Never add an entry to .vigieignore yourself: accepting a known risk is the user's decision.`;

const packageItem = {
  type: 'object',
  properties: {
    ecosystem: { type: 'string', description: 'npm, PyPI, Maven, Go, crates.io, NuGet, Packagist, RubyGems, Pub or Hex' },
    name: { type: 'string', description: 'Package name as published, e.g. "lodash" or "org.apache.logging.log4j:log4j-core"' },
    version: { type: 'string', description: 'Exact version, e.g. "4.17.20"' },
  },
  required: ['ecosystem', 'name', 'version'],
};

export const TOOLS = [
  {
    name: 'check_packages',
    description: 'Check exact package versions for known vulnerabilities and malicious packages across all sources. Call it BEFORE installing or upgrading a dependency. Returns a prioritized report: what is wrong, whether it is exploited in real attacks, the version to upgrade to, and release signals (deprecated, published very recently).',
    inputSchema: { type: 'object', properties: { packages: { type: 'array', items: packageItem, minItems: 1, maxItems: 2000 } }, required: ['packages'] },
  },
  {
    name: 'check_project',
    description: 'Read the dependency files of a project folder and its sub-folders (package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock, package.json, requirements*.txt, poetry.lock, uv.lock, Pipfile.lock, pyproject.toml, Cargo.lock, go.mod, composer.lock, Gemfile.lock, gradle.lockfile, pom.xml, packages.lock.json, pubspec.lock) and check every package version found. Call it before declaring a task done when dependencies changed.',
    inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'Absolute path of the project folder. Defaults to the folder the server was started in.' } } },
  },
  {
    name: 'check_technologies',
    description: 'Keyword watch for things that are not packages (e.g. "PostgreSQL", "nginx", "Node.js", "Windows Server"): latest CERT-FR (French government) alerts and advisories, and vulnerabilities exploited in real attacks. Matches product names, not your exact version.',
    inputSchema: { type: 'object', properties: { keywords: { type: 'array', items: { type: 'string' }, minItems: 1, maxItems: 30 } }, required: ['keywords'] },
  },
  {
    name: 'vulnerability_details',
    description: 'Full details for one vulnerability id (CVE-…, GHSA-…, or any OSV id): description, affected versions, references, whether it is exploited, exploit probability, CERT-FR bulletins.',
    inputSchema: { type: 'object', properties: { id: { type: 'string' } }, required: ['id'] },
  },
  {
    name: 'list_sources',
    description: 'List the vulnerability databases Vigie queries and what each one covers.',
    inputSchema: { type: 'object', properties: {} },
  },
];

const OSV_ID = /^[A-Za-z][A-Za-z0-9]*(-[A-Za-z0-9]+)+$/;

export async function vulnerabilityDetails(id) {
  const raw = String(id ?? '').trim();
  if (!OSV_ID.test(raw) || raw.length > 60) throw new Error('Expected an id such as CVE-2021-44228 or GHSA-xxxx-xxxx-xxxx');
  // OSV ids are case-sensitive: GHSA-<lowercase>, everything else uppercase
  const osvId = /^GHSA-/i.test(raw) ? `GHSA-${raw.slice(5).toLowerCase()}` : raw.toUpperCase();
  const out = [];
  let cves = /^CVE-/.test(osvId) ? [osvId] : [];
  try {
    const v = await providers.osv.vulnerability(osvId);
    cves = [...new Set([...cves, ...[v.id, ...(v.aliases || [])].filter((a) => /^CVE-/.test(a))])];
    out.push(`# ${v.id}${v.aliases?.length ? ` (${v.aliases.join(', ')})` : ''}`);
    if (v.withdrawn) out.push(`WITHDRAWN on ${String(v.withdrawn).slice(0, 10)}: this advisory was retracted by its publisher.`);
    out.push(v.summary || '', `Severity: ${providers.osv.severityOf(v)}`, '', (v.details || '').slice(0, 1500), '');
    for (const a of (v.affected || []).slice(0, 12)) {
      if (!a.package) continue;
      const fixes = (a.ranges || []).flatMap((r) => (r.events || []).map((e) => e.fixed).filter(Boolean));
      out.push(`- Affects ${a.package.ecosystem} ${a.package.name}${fixes.length ? ` · fixed in ${fixes.join(', ')}` : ' · no fix published'}`);
    }
    out.push('', ...(v.references || []).slice(0, 6).map((r) => `- ${r.url}`));
  } catch (err) {
    out.push(err.status === 404 ? `OSV.dev has no record for ${osvId}.` : `OSV.dev could not be reached for ${osvId} (${String(err.message).slice(0, 80)}): this answer is incomplete.`);
  }
  const extra = [];
  try {
    const cat = await providers.kev.catalogue();
    for (const c of cves) {
      const e = cat.byCve.get(c);
      if (e) extra.push(`- EXPLOITED IN REAL ATTACKS (CISA KEV, listed ${e.added}${e.ransomware ? ', used by ransomware' : ''}). Required: ${e.action}`);
    }
  } catch { extra.push('- CISA KEV: unavailable.'); }
  try {
    if (cves.length) for (const [c, s] of await providers.epss.scores(cves)) extra.push(`- Exploit probability (EPSS) for ${c}: ${(s * 100).toFixed(1)}%`);
  } catch { extra.push('- EPSS: unavailable.'); }
  try {
    const idx = await providers.certfr.index();
    for (const c of cves) for (const b of idx.byCve.get(c) || []) extra.push(`- CERT-FR ${b.ref} · ${b.title} · ${b.link}`);
  } catch { extra.push('- CERT-FR: unavailable.'); }
  if (extra.length) out.push('', 'Other sources:', ...extra);
  return out.join('\n');
}

export async function callTool(name, args) {
  const a = args && typeof args === 'object' ? args : {};
  switch (name) {
    case 'check_packages': {
      if (!Array.isArray(a.packages) || !a.packages.length) throw new Error('"packages" must be a non-empty list of {ecosystem, name, version}');
      if (a.packages.length > 2000) throw new Error('Too many packages in one call (max 2000). Use check_project or split the list');
      const report = await checkPackages(a.packages);
      return { text: formatReport(report) };
    }
    case 'check_project': {
      if (a.path !== undefined && (typeof a.path !== 'string' || !a.path.trim())) throw new Error('"path" must be the path of the project folder');
      const { text } = await checkProject(a.path?.trim() || process.cwd());
      return { text };
    }
    case 'check_technologies': {
      if (!Array.isArray(a.keywords) || !a.keywords.length) throw new Error('"keywords" must be a non-empty list of product names');
      const t = await checkTechnologies(a.keywords);
      return { text: formatTechnologies(t) };
    }
    case 'vulnerability_details':
      return { text: await vulnerabilityDetails(a.id) };
    case 'list_sources':
      return { text: sourcesList().map((s) => `- ${s.name} — ${s.covers} (${s.url})`).join('\n') };
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

/** Handles one JSON-RPC message; returns the response object, or null for notifications. */
export async function handle(msg) {
  const reply = (result) => ({ jsonrpc: '2.0', id: msg.id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id: msg?.id ?? null, error: { code, message } });
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return fail(-32600, 'Invalid request');
  const isNotification = msg.id === undefined || msg.id === null;
  switch (msg.method) {
    case 'initialize':
      return reply({
        protocolVersion: PROTOCOLS.includes(msg.params?.protocolVersion) ? msg.params.protocolVersion : PROTOCOLS[0],
        capabilities: { tools: {} },
        serverInfo: { name: 'vigie', version: VERSION },
        instructions: INSTRUCTIONS,
      });
    case 'ping':
      return reply({});
    case 'tools/list':
      return reply({ tools: TOOLS });
    case 'tools/call':
      if (isNotification) return null;
      try {
        // text only: clients that receive structured content show it INSTEAD of the text, and the agent would lose the report
        const { text } = await callTool(msg.params?.name, msg.params?.arguments);
        return reply({ content: [{ type: 'text', text }], isError: false });
      } catch (err) {
        return reply({ content: [{ type: 'text', text: `Vigie could not run this check: ${String(err?.message || err).replace(/\.$/, '')}. Do not treat the packages as safe.` }], isError: true });
      }
    default:
      return isNotification ? null : fail(-32601, `Method not found: ${msg.method}`);
  }
}

export function main() {
  prune();
  // a client that goes away must not leave an error on the screen
  process.stdout.on('error', () => process.exit(0));
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity });
  let pending = Promise.resolve();
  const send = (obj) => process.stdout.write(JSON.stringify(obj) + '\n');
  rl.on('line', (line) => {
    if (!line.trim()) return;
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
      return;
    }
    if (Array.isArray(msg)) {
      send({ jsonrpc: '2.0', id: null, error: { code: -32600, message: 'Batch requests are not supported' } });
      return;
    }
    const work = handle(msg)
      .catch((err) => ({ jsonrpc: '2.0', id: msg?.id ?? null, error: { code: -32603, message: String(err?.message || err).slice(0, 200) } }))
      .then((res) => res && send(res));
    pending = Promise.all([pending, work.catch(() => {})]);
  });
  rl.on('close', () => pending.then(() => process.exit(0)));
}

const isMain = (() => {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
if (isMain) main();
