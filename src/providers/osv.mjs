// OSV.dev — open source vulnerabilities (aggregates GitHub advisories, PyPA, RustSec, Go, malicious packages…).
import { http, cached, pool, HOUR } from '../cache.mjs';
import { compareVersions } from '../versions.mjs';

export const meta = {
  id: 'osv',
  name: 'OSV.dev (Google / OpenSSF)',
  url: 'https://osv.dev',
  covers: 'Known vulnerabilities and malicious packages in open source packages, matched by exact version.',
};

const ECOSYSTEMS = {
  npm: 'npm', node: 'npm', pypi: 'PyPI', pip: 'PyPI', python: 'PyPI', maven: 'Maven', java: 'Maven',
  go: 'Go', golang: 'Go', cargo: 'crates.io', 'crates.io': 'crates.io', rust: 'crates.io',
  nuget: 'NuGet', packagist: 'Packagist', composer: 'Packagist', php: 'Packagist',
  rubygems: 'RubyGems', gem: 'RubyGems', ruby: 'RubyGems', pub: 'Pub', hex: 'Hex',
};

export function normalizeEcosystem(e) {
  return ECOSYSTEMS[String(e || '').toLowerCase()] || null;
}

const sameName = (a, b, eco) =>
  eco === 'PyPI'
    ? a.toLowerCase().replace(/[-_.]+/g, '-') === b.toLowerCase().replace(/[-_.]+/g, '-')
    : a === b;

/** For each package, the list of OSV ids that affect this exact version. */
export async function queryIds(pkgs) {
  const ids = pkgs.map(() => []);
  for (let start = 0; start < pkgs.length; start += 500) {
    const chunk = pkgs.slice(start, start + 500);
    let pending = chunk.map((p, i) => ({ i, token: undefined }));
    for (let page = 0; pending.length && page < 10; page++) {
      const res = await http('https://api.osv.dev/v1/querybatch', {
        method: 'POST',
        body: {
          queries: pending.map(({ i, token }) => ({
            package: { name: chunk[i].name, ecosystem: chunk[i].ecosystem },
            version: chunk[i].version,
            ...(token ? { page_token: token } : {}),
          })),
        },
      });
      const again = [];
      (res.results || []).forEach((r, k) => {
        const { i } = pending[k];
        for (const v of r.vulns || []) ids[start + i].push(v.id);
        if (r.next_page_token) again.push({ i, token: r.next_page_token });
      });
      pending = again;
    }
  }
  return ids;
}

export async function vulnerability(id) {
  const { value } = await cached(`osv:${id}`, 24 * HOUR, () =>
    http(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`),
  );
  return value;
}

export function fixedVersion(vuln, pkg) {
  const fixes = [];
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
          if (compareVersions(pkg.version, introduced) >= 0 && compareVersions(pkg.version, e.fixed) < 0) {
            return e.fixed;
          }
        }
      }
    }
  }
  const later = fixes.filter((f) => compareVersions(f, pkg.version) > 0).sort(compareVersions);
  return later[0] || null;
}

const SEVERITY = { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MODERATE: 'MEDIUM', MEDIUM: 'MEDIUM', LOW: 'LOW' };

export function summarize(vuln, pkg) {
  const aliases = [vuln.id, ...(vuln.aliases || [])];
  const raw =
    vuln.database_specific?.severity ||
    (vuln.affected || []).map((a) => a.ecosystem_specific?.severity || a.database_specific?.severity).find(Boolean);
  return {
    id: vuln.id,
    cves: [...new Set(aliases.filter((a) => /^CVE-\d{4}-\d+$/.test(a)))],
    malicious: vuln.id.startsWith('MAL-'),
    severity: SEVERITY[String(raw || '').toUpperCase()] || 'UNKNOWN',
    summary: (vuln.summary || vuln.details || '').replace(/\s+/g, ' ').trim().slice(0, 240),
    fixedIn: fixedVersion(vuln, pkg),
    url: `https://osv.dev/vulnerability/${vuln.id}`,
  };
}

/** Full check: per package, the summarized vulnerabilities. */
export async function check(pkgs) {
  const idLists = await queryIds(pkgs);
  const unique = [...new Set(idLists.flat())];
  const details = new Map();
  await pool(unique, 8, async (id) => details.set(id, await vulnerability(id)));
  return idLists.map((list, i) => mergeDuplicates(list.map((id) => summarize(details.get(id), pkgs[i]))));
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
