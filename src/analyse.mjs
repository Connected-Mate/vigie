// Cross-checks packages against every provider and builds one prioritized report.
import * as osv from './providers/osv.mjs';
import * as kev from './providers/kev.mjs';
import * as epss from './providers/epss.mjs';
import * as certfr from './providers/certfr.mjs';
import * as depsdev from './providers/depsdev.mjs';
import { maxVersion, compareVersions, isMajorBump } from './versions.mjs';
import { within } from './cache.mjs';

export const providers = { osv, kev, epss, certfr, depsdev };
export const sourcesList = () => Object.values(providers).map((p) => p.meta);

const PRIORITY_LABEL = { 0: 'ACT NOW', 1: 'HIGH', 2: 'MEDIUM', 3: 'LOW' };
const SIGNALS_MAX = 40; // release signals are asked one package at a time: only for short lists
const FRESH_DAYS = 3;
const message = (err) => String(err?.message || err).slice(0, 160);
const keyOf = (p) => `${p.ecosystem}|${p.name}|${p.version}`;

export function normalizePackages(inputs) {
  const packages = [];
  const skipped = [];
  const seen = new Map();
  for (const raw of Array.isArray(inputs) ? inputs : []) {
    const name = String(raw?.name ?? '').trim();
    const version = String(raw?.version ?? '').trim().replace(/^[v=^~]+/, '');
    const ecosystem = osv.normalizeEcosystem(raw?.ecosystem);
    if (!name) skipped.push({ input: raw, reason: 'missing package name' });
    else if (!ecosystem) skipped.push({ input: raw, reason: `unknown ecosystem "${raw?.ecosystem ?? ''}" (use npm, PyPI, Maven, Go, crates.io, NuGet, Packagist, RubyGems, Pub, Hex)` });
    else if (!/^\d/.test(version) || /[\s<>|*,]/.test(version)) skipped.push({ input: raw, reason: 'missing or non-exact version (an exact version is required, e.g. 4.17.20)' });
    else if (name.length > 214 || version.length > 100 || /[\s\u0000-\u001f]/.test(name)) skipped.push({ input: raw, reason: 'not a valid package name or version' });
    else {
      const key = `${ecosystem}|${name}|${version}`;
      const pkg = seen.get(key);
      const extra = { ...(raw.file ? { files: [raw.file] } : {}), ...(raw.via ? { via: raw.via } : {}) };
      if (!pkg) {
        const fresh = { ecosystem, name, version, ...extra };
        seen.set(key, fresh);
        packages.push(fresh);
      } else if (raw.file && !(pkg.files || []).includes(raw.file)) pkg.files = [...(pkg.files || []), raw.file];
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

function actionFor(pkg, vulns, target) {
  if (vulns.some((v) => v.malicious)) {
    return `Remove ${pkg.name} immediately: this version is flagged as a malicious package. Do not run it; rotate any secret it could have read.`;
  }
  const fixed = vulns.filter((v) => v.fixedIn).length;
  const unfixed = vulns.filter((v) => !v.fixedIn).map((v) => v.id);
  const parts = [];
  if (target) {
    const major = isMajorBump(pkg.version, target.version) ? ' This is a major version change: read its changelog, it may break code.' : '';
    const scope = `fixes ${fixed} of ${vulns.length}`;
    if (target.state === 'clean') parts.push(`Upgrade ${pkg.name} to ${target.version} (${scope}; that version has no known vulnerability today).${major}`);
    else if (target.state === 'latest') parts.push(`Upgrade ${pkg.name} to ${target.version}, the current release (${scope}; the first fixed version ${target.minimal} still has other known vulnerabilities).${major}`);
    else if (target.state === 'dirty') parts.push(`Upgrade ${pkg.name} to ${target.version} or later (${scope}), then check the version you picked again: ${target.version} itself still has ${target.left} other known vulnerabilit${target.left > 1 ? 'ies' : 'y'}.${major}`);
    else parts.push(`Upgrade ${pkg.name} to ${target.version} or later (${scope}).${major}`);
  }
  if (unfixed.length) parts.push(`No fixed version published for ${unfixed.join(', ')}: replace the package or apply the mitigation described in the advisory.`);
  return parts.join(' ');
}

/** Checks that the version we recommend is itself free of known vulnerabilities (one extra question to OSV). */
async function pickTargets(findings, p) {
  const wanted = findings
    .map((f) => {
      const fixes = f.vulnerabilities.map((v) => v.fixedIn).filter(Boolean);
      return fixes.length && !f.vulnerabilities.some((v) => v.malicious) ? { f, version: maxVersion(fixes, f.package.ecosystem) } : null;
    })
    .filter(Boolean);
  const targets = new Map(wanted.map((w) => [w.f, { version: w.version, state: 'unverified' }]));
  if (!wanted.length || typeof p.osv.queryIds !== 'function') return targets;
  try {
    const left = await p.osv.queryIds(wanted.map((w) => ({ ...w.f.package, version: w.version })));
    const retry = [];
    wanted.forEach((w, i) => {
      if (!left[i].length) targets.set(w.f, { version: w.version, state: 'clean' });
      else {
        targets.set(w.f, { version: w.version, state: 'dirty', left: left[i].length });
        retry.push(w);
      }
    });
    // the first fixed version is still affected by something else: is the current release clean?
    if (retry.length && retry.length <= 20 && typeof p.depsdev?.defaultVersion === 'function') {
      const latest = await Promise.all(retry.map((w) => p.depsdev.defaultVersion(w.f.package.ecosystem, w.f.package.name).catch(() => null)));
      const ask = retry.map((w, i) => ({ w, version: latest[i] })).filter((x) => x.version && compareVersions(x.version, x.w.version, x.w.f.package.ecosystem) > 0);
      if (ask.length) {
        const res = await p.osv.queryIds(ask.map((x) => ({ ...x.w.f.package, version: x.version })));
        ask.forEach((x, i) => {
          if (!res[i].length) targets.set(x.w.f, { version: x.version, state: 'latest', minimal: x.w.version });
        });
      }
    }
  } catch {
    /* the recommendation stays "or later", unverified */
  }
  return targets;
}

/** True when a finding or a vulnerability is listed in the project's .vigieignore. */
const ignoredBy = (ignore, pkg, v) =>
  ignore.has(v.id.toUpperCase()) || v.cves.some((c) => ignore.has(c)) || ignore.has(`${pkg.name}@${pkg.version}`.toUpperCase());

/**
 * @param inputs [{ecosystem,name,version}]
 * @param p providers (injectable for tests)
 * @param opts { softTimeoutMs, signals, ignore: [ids or name@version], now }
 */
export async function checkPackages(inputs, p = providers, opts = {}) {
  const { softTimeoutMs = 45000, signals = true, now = Date.now() } = opts;
  const ignore = new Set((opts.ignore || []).map((s) => String(s).toUpperCase()));
  const { packages, skipped } = normalizePackages(inputs);
  const sources = {};
  const report = { verdict: 'clean', checked: packages.length, skipped, sources, findings: [], signals: [], accepted: [] };
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
      const value = await within(softTimeoutMs, id, fn);
      sources[id] = { ok: true, ...(value?.stale ? { stale: true } : {}) };
      return value;
    } catch (err) {
      sources[id] = { ok: false, error: message(err) };
      return fallback;
    }
  };
  const wantSignals = signals && p.depsdev?.signals && packages.length <= SIGNALS_MAX;
  const [kevCat, epssScores, certIdx, sig] = await Promise.all([
    soft('kev', () => p.kev.catalogue(), { byCve: new Map() }),
    cves.length ? soft('epss', () => p.epss.scores(cves), new Map()) : new Map(),
    soft('certfr', () => p.certfr.index(), { byCve: new Map() }),
    wantSignals ? soft('depsdev', () => p.depsdev.signals(packages, now), new Map()) : new Map(),
  ]);

  packages.forEach((pkg, i) => {
    const s = sig.get(keyOf(pkg));
    if (s?.deprecated) report.signals.push({ package: pkg, kind: 'deprecated', text: `deprecated by its author${s.reason ? `: ${s.reason}` : ''}` });
    if (s && s.ageDays !== null && s.ageDays >= 0 && s.ageDays < FRESH_DAYS) {
      const hours = Math.max(1, Math.round(s.ageDays * 24));
      report.signals.push({ package: pkg, kind: 'fresh', text: `published ${hours} hour${hours > 1 ? 's' : ''} ago: too recent for the vulnerability databases to have reviewed it (hijacked releases are usually caught within days). Prefer the previous version unless you need this one.` });
    }
    if (!perPackage[i].length) return;
    const all = perPackage[i].map((v) => {
      const kevHit = v.cves.map((c) => kevCat.byCve.get(c)).find(Boolean);
      const score = v.cves.map((c) => epssScores.get(c)).filter((x) => x !== undefined && !Number.isNaN(x));
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
    // a malicious package can never be "accepted"
    const vulns = all.filter((v) => v.malicious || !ignoredBy(ignore, pkg, v));
    for (const v of all) if (!vulns.includes(v)) report.accepted.push({ package: pkg, id: v.id, priority: v.priority });
    if (!vulns.length) return;
    vulns.sort((a, b) => a.priority - b.priority);
    report.findings.push({ package: pkg, priority: vulns[0].priority, action: '', vulnerabilities: vulns });
  });

  const targets = await pickTargets(report.findings, p);
  for (const f of report.findings) f.action = actionFor(f.package, f.vulnerabilities, targets.get(f));
  report.findings.sort((a, b) => a.priority - b.priority || b.vulnerabilities.length - a.vulnerabilities.length || (a.package.name < b.package.name ? -1 : 1));
  if (report.findings.length) report.verdict = 'vulnerable';
  return report;
}

/** Findings that deserve to stop an install or fail a build: exploited, malicious, critical or high. */
export const highPriority = (report) => report.findings.filter((f) => f.priority <= 1);

/** Keyword watch for things that are not packages (a database engine, a web server, an OS…). */
export async function checkTechnologies(keywords, p = providers, { softTimeoutMs = 45000 } = {}) {
  const sources = {};
  const list = [...new Set((Array.isArray(keywords) ? keywords : []).map((k) => String(k ?? '').trim().slice(0, 80)).filter(Boolean))].slice(0, 30);
  const soft = async (id, fn) => {
    try {
      const value = await within(softTimeoutMs, id, fn);
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

const where = (pkg) => {
  const bits = [];
  if (pkg.via) bits.push(`pulled in by ${pkg.via}`);
  if (pkg.files?.length) bits.push(`in ${pkg.files.slice(0, 3).join(', ')}${pkg.files.length > 3 ? ` and ${pkg.files.length - 3} more` : ''}`);
  return bits.length ? ` — ${bits.join(', ')}` : '';
};

export function formatReport(r, { maxPackages = 25, full = false } = {}) {
  if (full) maxPackages = Infinity;
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
    const high = r.findings.filter((f) => f.priority === 1).length;
    const tail = [urgent && `${urgent} package(s) need action NOW`, high && `${high} high priority`].filter(Boolean).join(', ');
    out.push(`VERDICT: ${count} known vulnerabilit${count > 1 ? 'ies' : 'y'} in ${r.findings.length} of ${r.checked} package version(s)${tail ? ` — ${tail}` : ''}.`);
  }
  r.findings.slice(0, maxPackages).forEach((f, rank) => {
    // the most urgent packages in detail, the rest shorter, so a large project stays readable
    const shown = full ? Infinity : rank < 10 ? 8 : 3;
    out.push('', `## [${PRIORITY_LABEL[f.priority]}] ${f.package.name}@${f.package.version} (${f.package.ecosystem})${where(f.package)}`, `What to do: ${f.action}`);
    for (const v of f.vulnerabilities.slice(0, shown)) {
      const flags = [
        v.malicious && 'MALICIOUS PACKAGE',
        v.exploited && `exploited in real attacks${v.ransomware ? ' (ransomware)' : ''}`,
        v.epss !== null && v.epss >= 0.01 && `exploit probability ${(v.epss * 100).toFixed(0)}%`,
        ...v.certfr.map((b) => `CERT-FR ${b.ref}`),
      ].filter(Boolean);
      out.push(`- ${v.id}${v.cves.length ? ` (${v.cves.join(', ')})` : ''} · severity ${v.severity}${v.malicious ? '' : v.fixedIn ? ` · fixed in ${v.fixedIn}` : ' · no fix published'}${flags.length ? ` · ${flags.join(' · ')}` : ''}`);
      if (v.summary) out.push(`  ${v.summary.slice(0, 160)}`);
      out.push(`  ${v.url}`);
    }
    if (f.vulnerabilities.length > shown) out.push(`- … and ${f.vulnerabilities.length - shown} more for this package.`);
  });
  if (r.findings.length > maxPackages) {
    out.push('', `… and ${r.findings.length - maxPackages} more affected package(s), lower priority: ${r.findings.slice(maxPackages, maxPackages + 60).map((f) => `${f.package.name}@${f.package.version}`).join(', ')}${r.findings.length > maxPackages + 60 ? ', …' : ''}`);
  }
  if (r.signals?.length) {
    out.push('', 'Worth knowing (not vulnerabilities):', ...r.signals.slice(0, 15).map((s) => `- ${s.package.name}@${s.package.version}: ${s.text}`));
  }
  if (r.accepted?.length) {
    out.push('', `Accepted by .vigieignore, not counted above (${r.accepted.length}): ${r.accepted.slice(0, 30).map((a) => `${a.id} in ${a.package.name}@${a.package.version}`).join(', ')}${r.accepted.length > 30 ? ', …' : ''}`);
  }
  if (r.skipped.length) {
    out.push('', `Not checked (${r.skipped.length}):`, ...r.skipped.slice(0, 15).map((s) => `- ${String(s.input?.name ?? JSON.stringify(s.input)).slice(0, 80)}: ${s.reason}`));
  }
  out.push('', 'Sources:', ...sourceLines(r.sources));
  out.push('', 'Limits: only publicly known vulnerabilities in published packages are covered — not flaws in your own code, not misconfiguration, not undisclosed vulnerabilities.');
  return out.join('\n');
}

/** A small machine-readable summary (the full detail is in the text, sending it twice would flood an agent). */
export function compactReport(r) {
  return {
    verdict: r.verdict,
    checked: r.checked,
    vulnerabilities: r.findings.reduce((n, f) => n + f.vulnerabilities.length, 0),
    affected: r.findings.length,
    high_priority: highPriority(r).length,
    sources: r.sources,
    findings: r.findings.slice(0, 50).map((f) => ({
      ecosystem: f.package.ecosystem,
      name: f.package.name,
      version: f.package.version,
      priority: PRIORITY_LABEL[f.priority],
      action: f.action,
      ids: f.vulnerabilities.slice(0, 20).map((v) => v.id),
    })),
    signals: (r.signals || []).slice(0, 20).map((s) => ({ name: s.package.name, version: s.package.version, kind: s.kind })),
    accepted: (r.accepted || []).length,
    skipped: r.skipped.length,
  };
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
  if (!t.results.length) out.push('', 'No keyword given.');
  out.push('', 'Sources:', ...sourceLines(t.sources));
  out.push('', 'Limits: CERT-FR only exposes its latest bulletins; an empty result is not a proof of safety.');
  return out.join('\n');
}

/** Reads a project folder and checks it. Shared by the MCP tool, the CLI and the hook. */
export async function checkProject(dir, { recursive = true, full = false, ...opts } = {}, p = providers) {
  const { readProject, readIgnore } = await import('./projet.mjs');
  const project = await readProject(dir, { recursive });
  const ignore = [...(opts.ignore || []), ...(await readIgnore(project.root))];
  const header = [`Project: ${project.root}`, ...project.files.slice(0, 40).map((f) => `- ${f.file}: ${f.packages} package version(s)`)];
  if (project.files.length > 40) header.push(`- … and ${project.files.length - 40} more dependency files`);
  header.push(...project.notes.map((n) => `Note: ${n}`), '', '');
  if (!project.packages.length) {
    const report = { verdict: 'incomplete', checked: 0, skipped: [], sources: {}, findings: [], signals: [], accepted: [] };
    return { project, report, text: [...header, 'VERDICT: INCOMPLETE — nothing to check in this folder.'].join('\n') };
  }
  const report = await checkPackages(project.packages, p, { ...opts, ignore, signals: false });
  return { project, report, text: header.join('\n') + formatReport(report, { full }) };
}
