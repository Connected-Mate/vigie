// Loose version comparison, good enough for npm (semver) and most PyPI / Maven versions.

function parse(v) {
  const s = String(v).trim().replace(/^[v=]+/i, '').split('+')[0];
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

/** Returns -1, 0 or 1. */
export function compareVersions(a, b) {
  const pa = parse(a);
  const pb = parse(b);
  for (let i = 0; i < Math.max(pa.nums.length, pb.nums.length); i++) {
    const x = pa.nums[i] ?? 0;
    const y = pb.nums[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return cmpPre(pa.pre, pb.pre);
}

export function maxVersion(list) {
  return list.reduce((best, v) => (best === null || compareVersions(v, best) > 0 ? v : best), null);
}
