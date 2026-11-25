// OSV.dev — open source vulnerabilities (aggregates GitHub advisories, PyPA, RustSec, Go, malicious packages…).
import { http, cached, pool, DAY } from '../cache.mjs';
import { compareVersions } from '../versions.mjs';
import { cvss3Score, severityOfScore } from '../cvss.mjs';
import { cvss4Score } from '../cvss4.mjs';

export const meta = {
  id: 'osv',
  name: 'OSV.dev (Google / OpenSSF)',
  url: 'https://osv.dev',
  covers: 'Known vulnerabilities and malicious packages in open source packages, matched on the exact version.',
};

// A mirror of the OSV API can be used instead (same paths). Also used by the tests.
const api = () => (process.env.VIGIE_OSV_API || 'https://api.osv.dev').replace(/\/+$/, '');

const ECOSYSTEMS = {
  npm: 'npm', node: 'npm', pypi: 'PyPI', pip: 'PyPI', python: 'PyPI', maven: 'Maven', java: 'Maven',
  go: 'Go', golang: 'Go', cargo: 'crates.io', 'crates.io': 'crates.io', crates: 'crates.io', rust: 'crates.io',
  nuget: 'NuGet', dotnet: 'NuGet', packagist: 'Packagist', composer: 'Packagist', php: 'Packagist',
  rubygems: 'RubyGems', gem: 'RubyGems', ruby: 'RubyGems', pub: 'Pub', dart: 'Pub', hex: 'Hex',
};

export function normalizeEcosystem(e) {
  return ECOSYSTEMS[String(e || '').trim().toLowerCase()] || null;
}

const pyName = (n) => n.toLowerCase().replace(/[-_.]+/g, '-');
const sameName = (a, b, eco) => (eco === 'PyPI' ? pyName(a) === pyName(b) : eco === 'NuGet' || eco === 'Packagist' ? a.toLowerCase() === b.toLowerCase() : a === b);

/** For each package, the list of { id, modified } that affect this exact version. */
export async function queryIds(pkgs) {
  const ids = pkgs.map(() => []);
  const chunks = [];
  for (let start = 0; start < pkgs.length; start += 500) chunks.push(start);
  await pool(chunks, 3, async (start) => {
    const chunk = pkgs.slice(start, start + 500);
    let pending = chunk.map((p, i) => ({ i, token: undefined }));
    for (let page = 0; pending.length && page < 20; page++) {
      const res = await http(`${api()}/v1/querybatch`, {
        method: 'POST',
        timeoutMs: 30000,
        body: {
          queries: pending.map(({ i, token }) => ({
            package: { name: chunk[i].name, ecosystem: chunk[i].ecosystem },
            version: chunk[i].version,
            ...(token ? { page_token: token } : {}),
          })),
        },
      });
      if (!Array.isArray(res?.results) || res.results.length !== pending.length) throw new Error('unexpected answer from OSV.dev');
      const again = [];
      res.results.forEach((r, k) => {
        const { i } = pending[k];
        for (const v of r?.vulns || []) if (v?.id) ids[start + i].push({ id: v.id, modified: v.modified || '' });
        if (r?.next_page_token) again.push({ i, token: r.next_page_token });
      });
      pending = again;
    }
  });
  return ids;
}

/** Full record of one vulnerability. Cached per revision: a modified advisory is downloaded again. */
export async function vulnerability(id, modified = '') {
  const { value } = await cached(`osv:${id}:${modified}`, modified ? 30 * DAY : DAY, () =>
    http(`${api()}/v1/vulns/${encodeURIComponent(id)}`),
  );
  return value;
}

export function fixedVersion(vuln, pkg) {
  const fixes = [];
  const cmp = (a, b) => compareVersions(a, b, pkg.ecosystem);
  for (const a of vuln.affected || []) {
    if (!a.package || a.package.ecosystem?.split(':')[0] !== pkg.ecosystem) continue;
    if (!sameName(a.package.name, pkg.name, pkg.ecosystem)) continue;
    for (const r of a.ranges || []) {
      if (r.type === 'GIT') continue;
      let introduced = '0';
      for (const e of r.events || []) {
        if (e.introduced !== undefined) introduced = e.introduced;
        if (e.fixed !== undefined) {
          fixes.push(e.fixed);
          if (cmp(pkg.version, introduced) >= 0 && cmp(pkg.version, e.fixed) < 0) return e.fixed;
        }
      }
    }
  }
  const later = fixes.filter((f) => cmp(f, pkg.version) > 0).sort(cmp);
  return later[0] || null;
}

const SEVERITY = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MODERATE: 'MEDIUM', MEDIUM: 'MEDIUM', LOW: 'LOW' };

export function severityOf(vuln) {
  const word =
    vuln.database_specific?.severity ||
    (vuln.affected || []).map((a) => a.ecosystem_specific?.severity || a.database_specific?.severity).find(Boolean);
  if (SEVERITY[String(word || '').toUpperCase()]) return SEVERITY[String(word).toUpperCase()];
  const vectors = [
    ...(vuln.severity || []),
    ...(vuln.affected || []).flatMap((a) => a.severity || []),
  ].map((s) => s?.score);
  for (const a of vuln.affected || []) if (a.database_specific?.cvss) vectors.push(a.database_specific.cvss);
  // No severity word: computed from the CVSS 3 or CVSS 4 vectors; when an advisory carries several, the highest counts.
  const scores = vectors.map((x) => cvss3Score(x) ?? cvss4Score(x)).filter((x) => x !== null);
  return (scores.length && severityOfScore(Math.max(...scores))) || 'UNKNOWN';
}

export function summarize(vuln, pkg) {
  const aliases = [vuln.id, ...(vuln.aliases || [])];
  return {
    id: vuln.id,
    cves: [...new Set(aliases.filter((a) => /^CVE-\d{4}-\d+$/.test(a)))],
    malicious: vuln.id.startsWith('MAL-'),
    severity: severityOf(vuln),
    summary: (vuln.summary || vuln.details || '').replace(/\s+/g, ' ').trim().slice(0, 240),
    fixedIn: fixedVersion(vuln, pkg),
    url: `https://osv.dev/vulnerability/${vuln.id}`,
  };
}

/** Full check: per package, the summarized vulnerabilities. */
export async function check(pkgs) {
  const idLists = await queryIds(pkgs);
  const unique = new Map(idLists.flat().map((v) => [v.id, v.modified]));
  const details = new Map();
  await pool([...unique], 10, async ([id, modified]) => details.set(id, await vulnerability(id, modified)));
  return idLists.map((list, i) =>
    mergeDuplicates(
      list
        .map(({ id }) => details.get(id))
        .filter((v) => v && v.id && !v.withdrawn)
        .map((v) => summarize(v, pkgs[i])),
    ),
  );
}

/** The same flaw is often published by several databases (GHSA, PYSEC, CVE…): keep one entry per flaw. */
export function mergeDuplicates(vulns) {
  const groups = new Map();
  for (const v of vulns) {
    const key = v.cves.length ? v.cves.slice().sort().join(',') : v.id;
    const kept = groups.get(key);
    if (!kept) {
      groups.set(key, { ...v });
      continue;
    }
    const preferNew = !kept.id.startsWith('GHSA-') && v.id.startsWith('GHSA-');
    const a = preferNew ? v : kept;
    const b = preferNew ? kept : v;
    groups.set(key, {
      ...a,
      severity: a.severity !== 'UNKNOWN' ? a.severity : b.severity,
      fixedIn: a.fixedIn || b.fixedIn,
      summary: a.summary || b.summary,
      malicious: a.malicious || b.malicious,
    });
  }
  return [...groups.values()];
}
