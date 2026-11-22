#!/usr/bin/env node
// Vigie — MCP server (stdio, JSON-RPC 2.0, one JSON message per line). No dependency.
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { realpathSync } from 'node:fs';
import { checkPackages, checkTechnologies, formatReport, formatTechnologies, sourcesList, providers } from './analyse.mjs';
import { readProject } from './projet.mjs';

const VERSION = '0.1.0';
const PROTOCOLS = ['2025-06-18', '2025-03-26', '2024-11-05'];

const INSTRUCTIONS = `Vigie checks known vulnerabilities across several public databases (OSV.dev, CISA KEV, EPSS, CERT-FR).
Rules for the agent:
1. BEFORE adding or upgrading any dependency, call check_packages with its exact version.
2. BEFORE declaring a task done in a project whose dependency files changed, call check_project on the project folder.
3. If the verdict is "vulnerable", apply the "What to do" lines (or tell the user why you cannot) before continuing.
4. If the verdict is "incomplete", say so to the user: never present unchecked packages as safe.`;

const packageItem = {
  type: 'object',
  properties: {
    ecosystem: { type: 'string', description: 'npm, PyPI, Maven, Go, crates.io, NuGet, Packagist or RubyGems' },
    name: { type: 'string', description: 'Package name as published, e.g. "lodash" or "org.apache.logging.log4j:log4j-core"' },
    version: { type: 'string', description: 'Exact version, e.g. "4.17.20"' },
  },
  required: ['ecosystem', 'name', 'version'],
};

export const TOOLS = [
  {
    name: 'check_packages',
    description: 'Check exact package versions for known vulnerabilities and malicious packages across all sources. Call it BEFORE installing or upgrading a dependency. Returns a prioritized report: what is wrong, whether it is exploited in real attacks, and the version to upgrade to.',
    inputSchema: { type: 'object', properties: { packages: { type: 'array', items: packageItem, minItems: 1, maxItems: 2000 } }, required: ['packages'] },
  },
  {
    name: 'check_project',
    description: 'Read the dependency files of a project folder (package-lock.json, pnpm-lock.yaml, yarn.lock, package.json, requirements.txt, poetry.lock, uv.lock, Cargo.lock, go.mod) and check every package version found. Call it before declaring a task done when dependencies changed.',
    inputSchema: { type: 'object', properties: { path: { type: 'string', description: 'Absolute path of the project folder' } }, required: ['path'] },
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

async function vulnerabilityDetails(id) {
  const clean = String(id || '').trim().toUpperCase().replace(/^(GHSA|MAL|PYSEC|RUSTSEC|GO)-.*/i, (m) => m);
  if (!/^[A-Z]+-[\w-]+$/i.test(clean)) throw new Error('Expected an id such as CVE-2021-44228 or GHSA-xxxx-xxxx-xxxx.');
  const osvId = /^GHSA-/i.test(clean) ? `GHSA-${clean.slice(5).toLowerCase()}` : clean;
  const out = [];
  let cves = /^CVE-/.test(clean) ? [clean] : [];
  try {
    const v = await providers.osv.vulnerability(osvId);
    cves = [...new Set([...cves, ...[v.id, ...(v.aliases || [])].filter((a) => /^CVE-/.test(a))])];
    out.push(`# ${v.id}${v.aliases?.length ? ` (${v.aliases.join(', ')})` : ''}`, v.summary || '', '', (v.details || '').slice(0, 1500), '');
    for (const a of (v.affected || []).slice(0, 12)) {
      if (!a.package) continue;
      const fixes = (a.ranges || []).flatMap((r) => (r.events || []).map((e) => e.fixed).filter(Boolean));
      out.push(`- Affects ${a.package.ecosystem} ${a.package.name}${fixes.length ? ` · fixed in ${fixes.join(', ')}` : ' · no fix published'}`);
    }
    out.push('', ...(v.references || []).slice(0, 6).map((r) => `- ${r.url}`));
  } catch (err) {
    out.push(`OSV.dev has no record for ${osvId} (${String(err.message).slice(0, 80)}).`);
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

export async function callTool(name, args = {}) {
  switch (name) {
    case 'check_packages': {
      if (!Array.isArray(args.packages) || !args.packages.length) throw new Error('"packages" must be a non-empty list of {ecosystem, name, version}.');
      if (args.packages.length > 2000) throw new Error('Too many packages in one call (max 2000). Use check_project or split the list.');
      const report = await checkPackages(args.packages);
      return { text: formatReport(report), structured: report };
    }
    case 'check_project': {
      if (typeof args.path !== 'string' || !args.path.trim()) throw new Error('"path" must be the absolute path of the project folder.');
      const project = await readProject(args.path);
      const header = [`Project: ${project.root}`, ...project.files.map((f) => `- ${f.file}: ${f.packages} package version(s)`), ...project.notes.map((n) => `Note: ${n}`), ''];
      if (!project.packages.length) {
        return { text: [...header, 'VERDICT: INCOMPLETE — nothing to check in this folder.'].join('\n'), structured: { verdict: 'incomplete', project } };
      }
      const report = await checkPackages(project.packages);
      return { text: header.join('\n') + formatReport(report), structured: { ...report, files: project.files, notes: project.notes } };
    }
    case 'check_technologies': {
      if (!Array.isArray(args.keywords) || !args.keywords.length) throw new Error('"keywords" must be a non-empty list of product names.');
      const t = await checkTechnologies(args.keywords);
      return { text: formatTechnologies(t), structured: t };
    }
    case 'vulnerability_details':
      return { text: await vulnerabilityDetails(args.id) };
    case 'list_sources':
      return { text: sourcesList().map((s) => `- ${s.name} — ${s.covers} (${s.url})`).join('\n'), structured: { sources: sourcesList() } };
    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

/** Handles one JSON-RPC message; returns the response object, or null for notifications. */
export async function handle(msg) {
  const reply = (result) => ({ jsonrpc: '2.0', id: msg.id, result });
  const fail = (code, message) => ({ jsonrpc: '2.0', id: msg.id ?? null, error: { code, message } });
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') return fail(-32600, 'Invalid request');
  const isNotification = msg.id === undefined;
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
      try {
        const { text, structured } = await callTool(msg.params?.name, msg.params?.arguments);
        return reply({ content: [{ type: 'text', text }], ...(structured ? { structuredContent: structured } : {}), isError: false });
      } catch (err) {
        return reply({ content: [{ type: 'text', text: `Vigie could not run this check: ${String(err.message || err)}. Do not treat the packages as safe.` }], isError: true });
      }
    default:
      return isNotification ? null : fail(-32601, `Method not found: ${msg.method}`);
  }
}

function main() {
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
    const work = handle(msg).then((res) => res && send(res));
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
