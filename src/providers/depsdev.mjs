// deps.dev (Google Open Source Insights) — facts about a published version that are not vulnerabilities:
// when it was published, whether its author deprecated it, which packages it pulls in, and the current default version.
import { http, cached, pool, HOUR, DAY } from '../cache.mjs';

export const meta = {
  id: 'depsdev',
  name: 'deps.dev (Google Open Source Insights)',
  url: 'https://deps.dev',
  covers: 'Release signals for a package version: deprecated by its author, published very recently, and the packages it pulls in.',
};

const SYSTEMS = { npm: 'npm', PyPI: 'pypi', Go: 'go', Maven: 'maven', 'crates.io': 'cargo', NuGet: 'nuget', RubyGems: 'rubygems' };
const BACK = { NPM: 'npm', PYPI: 'PyPI', GO: 'Go', MAVEN: 'Maven', CARGO: 'crates.io', NUGET: 'NuGet', RUBYGEMS: 'RubyGems' };
const BASE = 'https://api.deps.dev/v3/systems';

export const supports = (ecosystem) => Boolean(SYSTEMS[ecosystem]);
const versionUrl = (p) => `${BASE}/${SYSTEMS[p.ecosystem]}/packages/${encodeURIComponent(p.name)}/versions/${encodeURIComponent((p.ecosystem === 'Go' ? 'v' : '') + p.version)}`;

/** { publishedAt, deprecated, reason } or null when deps.dev does not know this version. */
export async function version(pkg) {
  if (!supports(pkg.ecosystem)) return null;
  const { value } = await cached(`depsdev:v:${pkg.ecosystem}:${pkg.name}:${pkg.version}`, 12 * HOUR, async () => {
    try {
      const j = await http(versionUrl(pkg), { timeoutMs: 10000 });
      return { publishedAt: j.publishedAt || null, deprecated: Boolean(j.isDeprecated), reason: String(j.deprecatedReason || '').slice(0, 200) };
    } catch (err) {
      if (err.status === 404) return { unknown: true };
      throw err;
    }
  });
  return value.unknown ? null : value;
}

/** Signals for a short list of packages: Map "eco|name|version" -> { deprecated, reason, ageDays }. */
export async function signals(pkgs, now = Date.now()) {
  const out = new Map();
  await pool(pkgs.filter((p) => supports(p.ecosystem)), 8, async (p) => {
    const v = await version(p);
    if (!v) return;
    const ageDays = v.publishedAt ? (now - Date.parse(v.publishedAt)) / DAY : null;
    out.set(`${p.ecosystem}|${p.name}|${p.version}`, { deprecated: v.deprecated, reason: v.reason, ageDays });
  });
  return out;
}

/** The version a plain install would bring today (the registry's default / latest stable). */
export async function defaultVersion(ecosystem, name) {
  if (!supports(ecosystem)) throw new Error(`deps.dev does not cover ${ecosystem}`);
  const { value } = await cached(`depsdev:d:${ecosystem}:${name}`, HOUR, async () => {
    const j = await http(`${BASE}/${SYSTEMS[ecosystem]}/packages/${encodeURIComponent(name)}`, { timeoutMs: 10000 });
    const def = (j.versions || []).find((v) => v.isDefault);
    if (!def) throw new Error(`no default version known for ${name}`);
    return def.versionKey.version.replace(/^v(?=\d)/, '');
  });
  return value;
}

/** Every package version a fresh install of `pkg` pulls in (itself excluded). Empty when unknown. */
export async function dependencies(pkg) {
  if (!supports(pkg.ecosystem)) return [];
  const { value } = await cached(`depsdev:t:${pkg.ecosystem}:${pkg.name}:${pkg.version}`, DAY, async () => {
    try {
      const j = await http(`${versionUrl(pkg)}:dependencies`, { timeoutMs: 12000 });
      return (j.nodes || [])
        .filter((n) => n.relation !== 'SELF' && n.versionKey?.version && BACK[n.versionKey.system])
        .map((n) => ({ ecosystem: BACK[n.versionKey.system], name: n.versionKey.name, version: n.versionKey.version.replace(/^v(?=\d)/, '') }));
    } catch (err) {
      if (err.status === 404) return [];
      throw err;
    }
  });
  return value;
}
