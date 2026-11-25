// CVSS v3.x base score from a vector string. Many advisories (Go, RustSec, PyPA) carry only the vector,
// not a severity word. CVSS v4 vectors are scored in cvss4.mjs.

const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
  PR: { U: { N: 0.85, L: 0.62, H: 0.27 }, C: { N: 0.85, L: 0.68, H: 0.5 } },
};

const roundUp = (x) => Math.ceil(x * 10 - 1e-9) / 10;

/** Returns the base score (0–10) or null when the vector is not a complete CVSS 3.x vector. */
export function cvss3Score(vector) {
  const m = String(vector || '').match(/^CVSS:3\.[01]\/(.+)$/);
  if (!m) return null;
  const v = Object.fromEntries(m[1].split('/').map((kv) => kv.split(':')));
  const av = W.AV[v.AV];
  const ac = W.AC[v.AC];
  const ui = W.UI[v.UI];
  const pr = W.PR[v.S]?.[v.PR];
  const [c, i, a] = [W.CIA[v.C], W.CIA[v.I], W.CIA[v.A]];
  if ([av, ac, ui, pr, c, i, a].some((x) => x === undefined)) return null;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = v.S === 'U' ? 6.42 * iss : 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  return roundUp(Math.min(v.S === 'U' ? impact + exploitability : 1.08 * (impact + exploitability), 10));
}

export function severityOfScore(score) {
  if (score === null || score === undefined) return null;
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return null;
}
