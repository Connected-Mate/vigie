// Version comparison per ecosystem. Vigie never decides "affected or not" with this (OSV.dev does that
// server-side, with each ecosystem's own rules); it is only used to pick the fixed version to recommend
// and to resolve "which version would this install bring".

const clean = (v) => String(v ?? '').trim().replace(/^[v=]+/i, '');
const sign = (n) => (n < 0 ? -1 : n > 0 ? 1 : 0);
const cmpNum = (a, b) => (a === b ? 0 : a < b ? -1 : 1);

// ---- semver-like (npm, crates.io, Go, NuGet, Packagist, Pub, Hex) -------------------------------------
function parseSemver(v) {
  const s = clean(v).split('+')[0];
  const m = s.match(/^(\d+(?:\.\d+)*)(.*)$/);
  if (!m) return { nums: [], pre: s };
  return { nums: m[1].split('.').map(Number), pre: m[2].replace(/^[-._]/, '') };
}

function cmpPre(a, b) {
  if (a === b) return 0;
  if (!a) return 1; // a release is greater than its pre-releases
  if (!b) return -1;
  const pa = a.split(/[.\-_]/);
  const pb = b.split(/[.\-_]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if (pa[i] === undefined) return -1;
    if (pb[i] === undefined) return 1;
    const na = /^\d+$/.test(pa[i]);
    const nb = /^\d+$/.test(pb[i]);
    if (na && nb) {
      if (+pa[i] !== +pb[i]) return +pa[i] < +pb[i] ? -1 : 1;
    } else if (pa[i] !== pb[i]) {
      if (na) return -1;
      if (nb) return 1;
      return pa[i] < pb[i] ? -1 : 1;
    }
  }
  return 0;
}

function cmpSemver(a, b) {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
    const c = cmpNum(pa.nums[i] ?? 0, pb.nums[i] ?? 0);
    if (c) return c;
  }
  return cmpPre(pa.pre, pb.pre);
}

// ---- PyPI (PEP 440): epochs, a/b/rc, .postN (after the release), .devN (before it) ---------------------
const PEP440 = /^(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-._]?(a|alpha|b|beta|c|rc|pre|preview)[-._]?(\d*))?(?:(?:[-._]?(?:post|rev|r)[-._]?(\d*))|-(\d+))?(?:[-._]?dev[-._]?(\d*))?$/i;
const PRE_RANK = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

function parsePep440(v) {
  const s = clean(v).split('+')[0];
  const m = s.match(PEP440);
  if (!m) return null;
  const hasPost = m[5] !== undefined || m[6] !== undefined;
  const hasDev = m[7] !== undefined;
  return {
    epoch: Number(m[1] || 0),
    nums: m[2].split('.').map(Number),
    // dev of a bare release sorts before every pre-release of it
    pre: m[3] ? [PRE_RANK[m[3].toLowerCase()], Number(m[4] || 0)] : hasDev && !hasPost ? [-1, 0] : [3, 0],
    post: hasPost ? Number(m[5] || m[6] || 0) + 1 : 0,
    dev: hasDev ? Number(m[7] || 0) : Infinity,
  };
}

function cmpPep440(a, b) {
  const pa = parsePep440(a);
  const pb = parsePep440(b);
  if (!pa || !pb) return cmpSemver(a, b);
  let c = cmpNum(pa.epoch, pb.epoch);
  if (c) return c;
  for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
    c = cmpNum(pa.nums[i] ?? 0, pb.nums[i] ?? 0);
    if (c) return c;
  }
  return cmpNum(pa.pre[0], pb.pre[0]) || cmpNum(pa.pre[1], pb.pre[1]) || cmpNum(pa.post, pb.post) || cmpNum(pa.dev, pb.dev);
}

export const isPrerelease = (v, ecosystem) => {
  if (ecosystem === 'PyPI') {
    const p = parsePep440(v);
    return !p || p.pre[0] !== 3 || p.dev !== Infinity;
  }
  return /^\d+(\.\d+)*[-._]?[a-z]/i.test(clean(v).split('+')[0]);
};

// ---- Maven: qualifiers (alpha < beta < milestone < rc < snapshot < release < sp), "-jre", ".Final" -----
const MAVEN_RANK = { alpha: 1, a: 1, beta: 2, b: 2, milestone: 3, m: 3, rc: 4, cr: 4, snapshot: 5, '': 6, final: 6, ga: 6, release: 6, sp: 7 };
const mavenTokens = (v) =>
  (clean(v).toLowerCase().match(/\d+|[a-z]+/g) || []).map((t) => (/^\d/.test(t) ? { n: Number(t) } : { rank: MAVEN_RANK[t] ?? 8, s: t }));

function cmpMaven(a, b) {
  const ta = mavenTokens(a);
  const tb = mavenTokens(b);
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const x = ta[i];
    const y = tb[i];
    if (x && y) {
      if ('n' in x && 'n' in y) {
        if (x.n !== y.n) return cmpNum(x.n, y.n);
      } else if ('n' in x) return 1; // a number is newer than any qualifier
      else if ('n' in y) return -1;
      else if (x.rank !== y.rank) return cmpNum(x.rank, y.rank);
      else if (x.s !== y.s && x.rank === 8) return x.s < y.s ? -1 : 1;
    } else {
      const only = x || y;
      const c = 'n' in only ? sign(only.n) : cmpNum(only.rank, 6); // missing = 0 / plain release
      if (c) return x ? c : -c;
    }
  }
  return 0;
}

// ---- RubyGems: any letter segment makes a pre-release (1.0.0.pre < 1.0.0) -----------------------------
const gemTokens = (v) => (clean(v).match(/\d+|[a-z]+/gi) || []).map((t) => (/^\d/.test(t) ? Number(t) : t.toLowerCase()));

function cmpGem(a, b) {
  const ta = gemTokens(a);
  const tb = gemTokens(b);
  for (let i = 0; i < Math.max(ta.length, tb.length); i++) {
    const x = ta[i] ?? 0;
    const y = tb[i] ?? 0;
    if (x === y) continue;
    if (typeof x === 'number' && typeof y === 'number') return cmpNum(x, y);
    if (typeof x === 'number') return 1;
    if (typeof y === 'number') return -1;
    return x < y ? -1 : 1;
  }
  return 0;
}

const BY_ECOSYSTEM = { PyPI: cmpPep440, Maven: cmpMaven, RubyGems: cmpGem };

/** Returns -1, 0 or 1. `ecosystem` is the OSV name (npm, PyPI, Maven…); semver rules when omitted. */
export function compareVersions(a, b, ecosystem) {
  return (BY_ECOSYSTEM[ecosystem] || cmpSemver)(a, b);
}

export function maxVersion(list, ecosystem) {
  return list.reduce((best, v) => (best === null || compareVersions(v, best, ecosystem) > 0 ? v : best), null);
}

/** True when going from `from` to `to` changes the first number (a "major" upgrade that may break things). */
export function isMajorBump(from, to) {
  const f = clean(from).match(/^(?:\d+!)?(\d+)/);
  const t = clean(to).match(/^(?:\d+!)?(\d+)/);
  return Boolean(f && t && f[1] !== t[1]);
}

// ---- npm ranges (^1.2.3, ~1.2, >=1 <2, 1.x, a || b, 1.0.0 - 2.0.0) -------------------------------------
const triple = (s) => {
  const m = String(s).match(/^[v=]*(\d+|[xX*])?(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([\w.-]+))?(?:\+[\w.-]+)?$/);
  if (!m) return null;
  const n = (x) => (x === undefined || /[xX*]/.test(x) ? null : Number(x));
  return { major: n(m[1]), minor: n(m[2]), patch: n(m[3]), pre: m[4] || '' };
};
const full = (t, pre = t.pre) => `${t.major ?? 0}.${t.minor ?? 0}.${t.patch ?? 0}${pre ? `-${pre}` : ''}`;

function comparatorsOf(token) {
  const m = token.match(/^(\^|~>?|>=|<=|>|<|=)?\s*(.+)$/);
  const op = m[1] || '';
  const t = triple(m[2]);
  if (!t) return null;
  const lo = full(t);
  const bump = (level) =>
    level === 'major' ? `${t.major + 1}.0.0-0` : level === 'minor' ? `${t.major}.${(t.minor ?? 0) + 1}.0-0` : `${t.major}.${t.minor}.${t.patch + 1}-0`;
  if (t.major === null) return [];
  const partial = t.minor === null ? 'major' : t.patch === null ? 'minor' : null;
  switch (op) {
    case '^': {
      const level = t.major > 0 || t.minor === null ? 'major' : t.minor > 0 || t.patch === null ? 'minor' : 'patch';
      return [['>=', lo], ['<', bump(level)]];
    }
    case '~':
    case '~>':
      return [['>=', lo], ['<', bump(t.minor === null ? 'major' : 'minor')]];
    case '>':
      return partial ? [['>=', bump(partial).replace(/-0$/, '')]] : [['>', lo]];
    case '<=':
      return partial ? [['<', bump(partial)]] : [['<=', lo]];
    case '>=':
    case '<':
      return [[op, lo]];
    default:
      return partial ? [['>=', lo], ['<', bump(partial)]] : [['=', lo]];
  }
}

const TEST = { '>=': (c) => c >= 0, '>': (c) => c > 0, '<=': (c) => c <= 0, '<': (c) => c < 0, '=': (c) => c === 0 };

/** npm semver range check. Returns null when the range cannot be understood (never guesses). */
export function satisfiesNpm(version, range) {
  const r = String(range ?? '').trim();
  if (!r || r === '*' || r === 'x' || r === 'latest') return !isPrerelease(version, 'npm');
  let understood = true;
  const ok = r.split('||').some((alt) => {
    const hyphen = alt.trim().match(/^(\S+)\s+-\s+(\S+)$/);
    const tokens = hyphen ? [`>=${hyphen[1]}`, `<=${hyphen[2]}`] : alt.trim().replace(/([<>=~^]+)\s+/g, '$1').split(/\s+/).filter(Boolean);
    const comps = [];
    for (const tok of tokens) {
      const c = comparatorsOf(tok);
      if (!c) {
        understood = false;
        return false;
      }
      comps.push(...c);
    }
    // a pre-release only matches when the range itself names a pre-release
    if (isPrerelease(version, 'npm') && !tokens.some((t) => /\d-[\w.]/.test(t))) return false;
    return comps.every(([op, v]) => TEST[op](cmpSemver(version, v)));
  });
  return understood ? ok : null;
}

/** PEP 440 specifier set ("&gt;=3.2,&lt;4", "~=3.2.1", "==3.2.*"). Returns null when not understood. */
export function satisfiesPep440(version, spec) {
  const clauses = String(spec ?? '').split(',').map((s) => s.trim()).filter(Boolean);
  for (const clause of clauses) {
    const m = clause.match(/^(~=|===?|!=|>=|<=|>|<)\s*([\w.!+*-]+)$/);
    if (!m) return null;
    const [, op, target] = m;
    if (target.endsWith('.*')) {
      const prefix = target.slice(0, -2).split('.');
      const mine = clean(version).split('.');
      const same = prefix.every((p, i) => Number(mine[i]) === Number(p));
      if (op === '!=' ? same : !same) return false;
      continue;
    }
    const c = cmpPep440(version, target);
    if (op === '~=') {
      const parts = target.split('.');
      if (parts.length < 2) return null;
      const upper = [...parts.slice(0, -2), String(Number(parts[parts.length - 2]) + 1)].join('.');
      if (c < 0 || cmpPep440(version, `${upper}.dev0`) >= 0) return false;
    } else if (op === '!=' ? c === 0 : !TEST[op.replace(/^===?$/, '=')](c)) return false;
  }
  return true;
}
