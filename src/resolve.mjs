// "Which exact version would this install bring?" — asked to the public registries, never guessed.
import { http, cached, HOUR } from './cache.mjs';
import { maxVersion, satisfiesNpm, satisfiesPep440, isPrerelease } from './versions.mjs';
import * as depsdev from './providers/depsdev.mjs';

const EXACT = /^\d+(\.\d+)*([-.+_]?[A-Za-z0-9][\w.+-]*)?$/;

async function npmPackument(name) {
  const { value } = await cached(`npm:p:${name}`, HOUR, async () => {
    const j = await http(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, {
      timeoutMs: 12000,
      headers: { accept: 'application/vnd.npm.install-v1+json' },
    });
    return { tags: j['dist-tags'] || {}, versions: Object.keys(j.versions || {}) };
  });
  return value;
}

async function resolveNpm(name, spec) {
  const s = String(spec || '').trim();
  if (/^\d+\.\d+\.\d+(-[\w.]+)?(\+[\w.]+)?$/.test(s)) return s;
  const doc = await npmPackument(name);
  if (!s || doc.tags[s]) return doc.tags[s || 'latest'];
  const matching = doc.versions.filter((v) => satisfiesNpm(v, s));
  if (doc.versions.some((v) => satisfiesNpm(v, s) === null)) throw new Error(`version "${s}" of ${name} is not understood`);
  // npm prefers the "latest" tag when it is inside the range
  if (doc.tags.latest && matching.includes(doc.tags.latest)) return doc.tags.latest;
  const best = maxVersion(matching, 'npm');
  if (!best) throw new Error(`no published version of ${name} matches "${s}"`);
  return best;
}

async function resolvePyPI(name, spec) {
  const s = String(spec || '').trim();
  const pin = s.match(/^(?:===?\s*)?(\d[\w.!+-]*)$/);
  if (pin) return pin[1];
  const { value } = await cached(`pypi:p:${name.toLowerCase()}`, HOUR, async () => {
    const j = await http(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { timeoutMs: 12000 });
    return {
      latest: j.info?.version,
      versions: Object.entries(j.releases || {}).filter(([, files]) => files.length && !files.every((f) => f.yanked)).map(([v]) => v),
    };
  });
  if (!s) return value.latest;
  const wantsPre = /\d(a|b|rc|\.dev)\d*/i.test(s);
  let unknown = false;
  const matching = value.versions.filter((v) => {
    const ok = satisfiesPep440(v, s);
    if (ok === null) unknown = true;
    return ok && (wantsPre || !isPrerelease(v, 'PyPI'));
  });
  if (unknown) throw new Error(`version "${s}" of ${name} is not understood`);
  const best = maxVersion(matching, 'PyPI');
  if (!best) throw new Error(`no published version of ${name} matches "${s}"`);
  return best;
}

/**
 * @param spec '' (latest), an exact version, or a range in the ecosystem's own syntax
 * @returns the exact version; throws when it cannot be determined
 */
export async function resolveVersion(ecosystem, name, spec = '') {
  const s = String(spec || '').trim();
  if (ecosystem === 'npm') return resolveNpm(name, s);
  if (ecosystem === 'PyPI') return resolvePyPI(name, s);
  const bare = s.replace(/^[v=]+/, '');
  if (EXACT.test(bare)) return bare;
  if (!s || s === 'latest') return depsdev.defaultVersion(ecosystem, name);
  throw new Error(`version "${s}" of ${name} is not an exact version`);
}
