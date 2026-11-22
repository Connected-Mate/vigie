// Cross-checks packages against every provider and builds one prioritized report.
import * as osv from './providers/osv.mjs';
import * as kev from './providers/kev.mjs';
import * as epss from './providers/epss.mjs';
import * as certfr from './providers/certfr.mjs';
import { maxVersion } from './versions.mjs';

export const providers = { osv, kev, epss, certfr };
export const sourcesList = () => Object.values(providers).map((p) => p.meta);

const PRIORITY_LABEL = { 0: 'ACT NOW', 1: 'HIGH', 2: 'MEDIUM', 3: 'LOW' };
const message = (err) => String(err?.message || err).slice(0, 160);

export function normalizePackages(inputs) {
  const packages = [];
  const skipped = [];
  const seen = new Set();
  for (const raw of inputs || []) {
    const name = String(raw?.name || '').trim();
    const version = String(raw?.version || '').trim().replace(/^[v=^~]+/, '');
    const ecosystem = osv.normalizeEcosystem(raw?.ecosystem);
    if (!name) skipped.push({ input: raw, reason: 'missing package name' });
    else if (!ecosystem) skipped.push({ input: raw, reason: `unknown ecosystem "${raw?.ecosystem ?? ''}" (use npm, PyPI, Maven, Go, crates.io, NuGet, Packagist, RubyGems)` });
    else if (!/^\d/.test(version)) skipped.push({ input: raw, reason: 'missing or non-exact version (an exact version is required, e.g. 4.17.20)' });
    else {
      const key = `${ecosystem}|${name}|${version}`;
      if (!seen.has(key)) {
        seen.add(key);
        packages.push({ ecosystem, name, version });
      }
    }
  }
  return { packages, skipped };
}

function priorityOf(v) {
  if (v.malicious || v.exploited || v.certfr.some((b) => b.kind === 'alerte' && !b.closed)) return 0;
  if (v.severity === 'CRITICAL' || v.severity === 'HIGH' || (v.epss ?? 0) >= 0.1) return 1;
  if (v.severity === 'LOW') return 3;
  return 2;
}

function actionFor(pkg, vulns) {
  if (vulns.some((v) => v.malicious)) {
    return `Remove ${pkg.name} immediately: this version is flagged as a malicious package. Do not run it; rotate any secret it could have read.`;
  }
  const fixes = vulns.map((v) => v.fixedIn).filter(Boolean);
  const unfixed = vulns.filter((v) => !v.fixedIn).map((v) => v.id);
  const parts = [];
  if (fixes.length) parts.push(`Upgrade ${pkg.name} to ${maxVersion(fixes)} or later (fixes ${fixes.length} of ${vulns.length}).`);
  if (unfixed.length) parts.push(`No fixed version published for ${unfixed.join(', ')}: replace the package or apply the mitigation described in the advisory.`);
  return parts.join(' ');
}

/**
 * @param inputs [{ecosystem,name,version}]
 * @param p providers (injectable for tests)
 */
export async function checkPackages(inputs, p = providers) {
  const { packages, skipped } = normalizePackages(inputs);
  const sources = {};
  const report = { verdict: 'clean', checked: packages.length, skipped, sources, findings: [] };
  if (!packages.length) {
    report.verdict = 'incomplete';
    return report;
  }

  let perPackage;
  try {
    perPackage = await p.osv.check(packages);
    sources.osv = { ok: true };
  } catch (err) {
    sources.osv = { ok: false, error: message(err) };
    report.verdict = 'incomplete';
    return report;
  }

  const cves = [...new Set(perPackage.flat().flatMap((v) => v.cves))];
  const soft = async (id, fn, fallback) => {
    try {
      const value = await fn();
      sources[id] = { ok: true, ...(value?.stale ? { stale: true } : {}) };
      return value;
    } catch (err) {
      sources[id] = { ok: false, error: message(err) };
      return fallback;
    }
  };
  const [kevCat, epssScores, certIdx] = await Promise.all([
    soft('kev', () => p.kev.catalogue(), { byCve: new Map() }),
    soft('epss', () => (cves.length ? p.epss.scores(cves) : new Map()), new Map()),
    soft('certfr', () => p.certfr.index(), { byCve: new Map() }),
  ]);

  packages.forEach((pkg, i) => {
    if (!perPackage[i].length) return;
    const vulns = perPackage[i].map((v) => {
      const kevHit = v.cves.map((c) => kevCat.byCve.get(c)).find(Boolean);
      const score = v.cves.map((c) => epssScores.get(c)).filter((x) => x !== undefined);
      const bulletins = [...new Map(v.cves.flatMap((c) => certIdx.byCve.get(c) || []).map((b) => [b.ref, b])).values()];
      const full = {
        ...v,
        exploited: Boolean(kevHit),
        ransomware: Boolean(kevHit?.ransomware),
        epss: score.length ? Math.max(...score) : null,
        certfr: bulletins.map((b) => ({ ref: b.ref, kind: b.kind, title: b.title, link: b.link, closed: b.closed })),
      };
      return { ...full, priority: priorityOf(full) };
    });
    vulns.sort((a, b) => a.priority - b.priority);
    report.findings.push({ package: pkg, priority: vulns[0].priority, action: actionFor(pkg, vulns), vulnerabilities: vulns });
  });
  report.findings.sort((a, b) => a.priority - b.priority || b.vulnerabilities.length - a.vulnerabilities.length);
  if (report.findings.length) report.verdict = 'vulnerable';
  return report;
}

/** Keyword watch for things that are not packages (a database engine, a web server, an OS…). */
export async function checkTechnologies(keywords, p = providers) {
  const sources = {};
  const list = [...new Set((keywords || []).map((k) => String(k).trim()).filter(Boolean))].slice(0, 30);
  const soft = async (id, fn) => {
    try {
      const value = await fn();
      sources[id] = { ok: true, ...(value?.stale ? { stale: true } : {}) };
      return value;
    } catch (err) {
      sources[id] = { ok: false, error: message(err) };
      return null;
    }
  };
  const [kevCat, certIdx] = await Promise.all([soft('kev', () => p.kev.catalogue()), soft('certfr', () => p.certfr.index())]);
  const results = list.map((keyword) => ({
    keyword,
    certfr: certIdx ? p.certfr.search(certIdx, keyword, 5) : [],
    exploited: kevCat ? p.kev.search(kevCat, keyword, 5) : [],
  }));
  return { sources, results };
}

const sourceLines = (sources) =>
  Object.entries(sources).map(([id, s]) => {
    const name = providers[id]?.meta.name || id;
    if (!s.ok) return `- ${name}: UNAVAILABLE (${s.error})`;
    return `- ${name}: ok${s.stale ? ' (source unreachable, older cached copy used)' : ''}`;
  });

export function formatReport(r, { maxPackages = 25 } = {}) {
  const out = [];
  const down = Object.values(r.sources).filter((s) => !s.ok).length;
  if (r.verdict === 'incomplete') {
    out.push('VERDICT: INCOMPLETE — the check could not be completed. Do NOT treat these packages as safe.');
    if (!r.checked) out.push('No valid package to check.');
  } else if (r.verdict === 'clean') {
    out.push(`VERDICT: no known vulnerability in the ${r.checked} package version(s) checked${down ? ' (some sources were unavailable, see below)' : ''}.`);
  } else {
    const count = r.findings.reduce((n, f) => n + f.vulnerabilities.length, 0);
    const urgent = r.findings.filter((f) => f.priority === 0).length;
    out.push(`VERDICT: ${count} known vulnerabilit${count > 1 ? 'ies' : 'y'} in ${r.findings.length} of ${r.checked} package version(s)${urgent ? ` — ${urgent} package(s) need action NOW` : ''}.`);
  }
  for (const f of r.findings.slice(0, maxPackages)) {
    out.push('', `## [${PRIORITY_LABEL[f.priority]}] ${f.package.name}@${f.package.version} (${f.package.ecosystem})`, `What to do: ${f.action}`);
    for (const v of f.vulnerabilities.slice(0, 8)) {
      const flags = [
        v.malicious && 'MALICIOUS PACKAGE',
        v.exploited && `exploited in real attacks${v.ransomware ? ' (ransomware)' : ''}`,
        v.epss !== null && v.epss >= 0.01 && `exploit probability ${(v.epss * 100).toFixed(0)}%`,
        ...v.certfr.map((b) => `CERT-FR ${b.ref}`),
      ].filter(Boolean);
      out.push(`- ${v.id}${v.cves.length ? ` (${v.cves.join(', ')})` : ''} · severity ${v.severity}${v.fixedIn ? ` · fixed in ${v.fixedIn}` : ' · no fix published'}${flags.length ? ` · ${flags.join(' · ')}` : ''}`);
      if (v.summary) out.push(`  ${v.summary}`);
      out.push(`  ${v.url}`);
    }
    if (f.vulnerabilities.length > 8) out.push(`- … and ${f.vulnerabilities.length - 8} more for this package.`);
  }
  if (r.findings.length > maxPackages) {
    out.push('', `… and ${r.findings.length - maxPackages} more affected package(s), lower priority: ${r.findings.slice(maxPackages).map((f) => `${f.package.name}@${f.package.version}`).join(', ')}`);
  }
  if (r.skipped.length) {
    out.push('', `Not checked (${r.skipped.length}):`, ...r.skipped.slice(0, 15).map((s) => `- ${s.input?.name ?? JSON.stringify(s.input)}: ${s.reason}`));
  }
  out.push('', 'Sources:', ...sourceLines(r.sources));
  out.push('', 'Limits: only publicly known vulnerabilities in published packages are covered — not flaws in your own code, not misconfiguration, not undisclosed vulnerabilities.');
  return out.join('\n');
}

export function formatTechnologies(t) {
  const out = ['Keyword watch (matched on product names, NOT on your exact versions: read each item and decide whether your version is concerned).'];
  for (const r of t.results) {
    out.push('', `## ${r.keyword}`);
    if (!r.certfr.length && !r.exploited.length) out.push('Nothing recent found for this keyword.');
    for (const b of r.certfr) {
      out.push(`- CERT-FR ${b.kind === 'alerte' ? (b.closed ? 'alert (closed)' : 'ALERT (open)') : 'advisory'} ${b.ref} · ${b.date} · ${b.title}${b.cves.length ? ` · ${b.cves.slice(0, 5).join(', ')}` : ''}`, `  ${b.link}`);
    }
    for (const e of r.exploited) {
      out.push(`- Exploited in real attacks: ${e.cve} · ${e.vendor} ${e.product} · ${e.name} · listed ${e.added}${e.ransomware ? ' · ransomware' : ''}`, `  Required: ${e.action}`);
    }
  }
  out.push('', 'Sources:', ...sourceLines(t.sources));
  out.push('', 'Limits: CERT-FR only exposes its latest bulletins; an empty result is not a proof of safety.');
  return out.join('\n');
}
