// CVSS v4.0 score from a vector string. Some advisories carry only a CVSS 4 vector and no severity word.
//
// The method is the one of the CVSS v4.0 specification (https://www.first.org/cvss/v4.0/specification-document):
// the vector falls in one of 270 "MacroVectors", each with a published score, and the score is then lowered
// according to how far the vector is from the most severe vector of its MacroVector.
// The MacroVector scores and the highest-severity vectors below are data from the reference calculator
// (https://github.com/RedHatProductSecurity/cvss-v4-calculator), Copyright (c) 2023 FIRST.ORG, Inc., Red Hat,
// and contributors, BSD 2-Clause license (full text in THIRD-PARTY-NOTICES.md). The code is a rewrite for Vigie.

const BASE = {
  AV: 'NALP', AC: 'LH', AT: 'NP', PR: 'NLH', UI: 'NPA',
  VC: 'NLH', VI: 'NLH', VA: 'NLH', SC: 'NLH', SI: 'NLH', SA: 'NLH',
};
const OPTIONAL = {
  E: 'XAPU', CR: 'XHML', IR: 'XHML', AR: 'XHML',
  MAV: 'XNALP', MAC: 'XLH', MAT: 'XNP', MPR: 'XNLH', MUI: 'XNPA',
  MVC: 'XHLN', MVI: 'XHLN', MVA: 'XHLN', MSC: 'XHLN', MSI: 'XSHLN', MSA: 'XSHLN',
};
// Supplemental metrics: accepted, never change the score.
const SUPPLEMENTAL = new Set(['S', 'AU', 'R', 'V', 'RE', 'U']);
// "Not defined" counts as the worst case for these.
const WORST = { E: 'A', CR: 'H', IR: 'H', AR: 'H' };

// How far each value is from the most severe one, in steps of 0.1.
const LEVEL = {
  AV: { N: 0, A: 1, L: 2, P: 3 }, PR: { N: 0, L: 1, H: 2 }, UI: { N: 0, P: 1, A: 2 },
  AC: { L: 0, H: 1 }, AT: { N: 0, P: 1 },
  VC: { H: 0, L: 1, N: 2 }, VI: { H: 0, L: 1, N: 2 }, VA: { H: 0, L: 1, N: 2 },
  SC: { H: 1, L: 2, N: 3 }, SI: { S: 0, H: 1, L: 2, N: 3 }, SA: { S: 0, H: 1, L: 2, N: 3 },
  CR: { H: 0, M: 1, L: 2 }, IR: { H: 0, M: 1, L: 2 }, AR: { H: 0, M: 1, L: 2 },
};

// Most severe vectors of each equivalence class.
const MAX = {
  eq1: [['AV:N/PR:N/UI:N'], ['AV:A/PR:N/UI:N', 'AV:N/PR:L/UI:N', 'AV:N/PR:N/UI:P'], ['AV:P/PR:N/UI:N', 'AV:A/PR:L/UI:P']],
  eq2: [['AC:L/AT:N'], ['AC:H/AT:N', 'AC:L/AT:P']],
  // eq3, then eq6
  eq36: [
    [['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H'], ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M']],
    [['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H'],
      ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M', 'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H', 'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M']],
    [null, ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H']],
  ],
  eq4: [['SC:H/SI:S/SA:S'], ['SC:H/SI:H/SA:H'], ['SC:L/SI:L/SA:L']],
};
// Depth of each equivalence class, in steps.
const DEPTH = { eq1: [1, 4, 5], eq2: [1, 2], eq36: [[7, 6], [8, 8], [null, 10]], eq4: [6, 5, 4] };

// MacroVector (EQ1 EQ2 EQ3 EQ4 EQ5 EQ6) = score.
const SCORES = Object.fromEntries(`
  000000=10 000001=9.9 000010=9.8 000011=9.5 000020=9.5 000021=9.2 000100=10 000101=9.6 000110=9.3 000111=8.7 000120=9.1 000121=8.1 000200=9.3 000201=9 000210=8.9 000211=8 000220=8.1 000221=6.8
  001000=9.8 001001=9.5 001010=9.5 001011=9.2 001020=9 001021=8.4 001100=9.3 001101=9.2 001110=8.9 001111=8.1 001120=8.1 001121=6.5 001200=8.8 001201=8 001210=7.8 001211=7 001220=6.9 001221=4.8
  002001=9.2 002011=8.2 002021=7.2 002101=7.9 002111=6.9 002121=5 002201=6.9 002211=5.5 002221=2.7
  010000=9.9 010001=9.7 010010=9.5 010011=9.2 010020=9.2 010021=8.5 010100=9.5 010101=9.1 010110=9 010111=8.3 010120=8.4 010121=7.1 010200=9.2 010201=8.1 010210=8.2 010211=7.1 010220=7.2 010221=5.3
  011000=9.5 011001=9.3 011010=9.2 011011=8.5 011020=8.5 011021=7.3 011100=9.2 011101=8.2 011110=8 011111=7.2 011120=7 011121=5.9 011200=8.4 011201=7 011210=7.1 011211=5.2 011220=5 011221=3
  012001=8.6 012011=7.5 012021=5.2 012101=7.1 012111=5.2 012121=2.9 012201=6.3 012211=2.9 012221=1.7
  100000=9.8 100001=9.5 100010=9.4 100011=8.7 100020=9.1 100021=8.1 100100=9.4 100101=8.9 100110=8.6 100111=7.4 100120=7.7 100121=6.4 100200=8.7 100201=7.5 100210=7.4 100211=6.3 100220=6.3 100221=4.9
  101000=9.4 101001=8.9 101010=8.8 101011=7.7 101020=7.6 101021=6.7 101100=8.6 101101=7.6 101110=7.4 101111=5.8 101120=5.9 101121=5 101200=7.2 101201=5.7 101210=5.7 101211=5.2 101220=5.2 101221=2.5
  102001=8.3 102011=7 102021=5.4 102101=6.5 102111=5.8 102121=2.6 102201=5.3 102211=2.1 102221=1.3
  110000=9.5 110001=9 110010=8.8 110011=7.6 110020=7.6 110021=7 110100=9 110101=7.7 110110=7.5 110111=6.2 110120=6.1 110121=5.3 110200=7.7 110201=6.6 110210=6.8 110211=5.9 110220=5.2 110221=3
  111000=8.9 111001=7.8 111010=7.6 111011=6.7 111020=6.2 111021=5.8 111100=7.4 111101=5.9 111110=5.7 111111=5.7 111120=4.7 111121=2.3 111200=6.1 111201=5.2 111210=5.7 111211=2.9 111220=2.4 111221=1.6
  112001=7.1 112011=5.9 112021=3 112101=5.8 112111=2.6 112121=1.5 112201=2.3 112211=1.3 112221=0.6
  200000=9.3 200001=8.7 200010=8.6 200011=7.2 200020=7.5 200021=5.8 200100=8.6 200101=7.4 200110=7.4 200111=6.1 200120=5.6 200121=3.4 200200=7 200201=5.4 200210=5.2 200211=4 200220=4 200221=2.2
  201000=8.5 201001=7.5 201010=7.4 201011=5.5 201020=6.2 201021=5.1 201100=7.2 201101=5.7 201110=5.5 201111=4.1 201120=4.6 201121=1.9 201200=5.3 201201=3.6 201210=3.4 201211=1.9 201220=1.9 201221=0.8
  202001=6.4 202011=5.1 202021=2 202101=4.7 202111=2.1 202121=1.1 202201=2.4 202211=0.9 202221=0.4
  210000=8.8 210001=7.5 210010=7.3 210011=5.3 210020=6 210021=5 210100=7.3 210101=5.5 210110=5.9 210111=4 210120=4.1 210121=2 210200=5.4 210201=4.3 210210=4.5 210211=2.2 210220=2 210221=1.1
  211000=7.5 211001=5.5 211010=5.8 211011=4.5 211020=4 211021=2.1 211100=6.1 211101=5.1 211110=4.8 211111=1.8 211120=2 211121=0.9 211200=4.6 211201=1.8 211210=1.7 211211=0.7 211220=0.8 211221=0.2
  212001=5.3 212011=2.4 212021=1.4 212101=2.4 212111=1.2 212121=0.5 212201=1 212211=0.3 212221=0.1
`.trim().split(/\s+/).map((kv) => { const [k, s] = kv.split('='); return [k, Number(s)]; }));

function parse(vector) {
  const parts = String(vector || '').trim().split('/');
  if (parts.shift() !== 'CVSS:4.0') return null;
  const m = {};
  for (const part of parts) {
    const [key, value, extra] = part.split(':');
    if (!value || extra !== undefined || key in m) return null;
    if (SUPPLEMENTAL.has(key)) continue;
    const allowed = Object.hasOwn(BASE, key) ? BASE[key] : Object.hasOwn(OPTIONAL, key) ? OPTIONAL[key] : null;
    if (!allowed || value.length !== 1 || !allowed.includes(value)) return null;
    m[key] = value;
  }
  if (Object.keys(BASE).some((k) => !m[k])) return null;
  return m;
}

/** Returns the CVSS 4.0 score (0–10) or null when the vector is not a complete, valid CVSS 4.0 vector. */
export function cvss4Score(vector) {
  const m = parse(vector);
  if (!m) return null;
  // Effective value: the environmental "modified" metric wins, then the worst case for what is not defined.
  const eff = (k) => {
    const modified = m['M' + k];
    if (modified && modified !== 'X') return modified;
    if (WORST[k] && (!m[k] || m[k] === 'X')) return WORST[k];
    return m[k];
  };
  const v = Object.fromEntries([...Object.keys(BASE), 'E', 'CR', 'IR', 'AR'].map((k) => [k, eff(k)]));

  if (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'].every((k) => v[k] === 'N')) return 0;

  const anyN = v.AV === 'N' || v.PR === 'N' || v.UI === 'N';
  const eq1 = v.AV === 'N' && v.PR === 'N' && v.UI === 'N' ? 0 : anyN && v.AV !== 'P' ? 1 : 2;
  const eq2 = v.AC === 'L' && v.AT === 'N' ? 0 : 1;
  const eq3 = v.VC === 'H' && v.VI === 'H' ? 0 : v.VC === 'H' || v.VI === 'H' || v.VA === 'H' ? 1 : 2;
  const eq4 = m.MSI === 'S' || m.MSA === 'S' ? 0 : v.SC === 'H' || v.SI === 'H' || v.SA === 'H' ? 1 : 2;
  const eq5 = { A: 0, P: 1, U: 2 }[v.E];
  const eq6 = (v.CR === 'H' && v.VC === 'H') || (v.IR === 'H' && v.VI === 'H') || (v.AR === 'H' && v.VA === 'H') ? 0 : 1;

  const key = (a, b, c, d, e, f) => `${a}${b}${c}${d}${e}${f}`;
  const value = SCORES[key(eq1, eq2, eq3, eq4, eq5, eq6)];
  if (value === undefined) return null;

  // Score of the next less severe MacroVector along each class (undefined when there is none).
  const lower1 = SCORES[key(eq1 + 1, eq2, eq3, eq4, eq5, eq6)];
  const lower2 = SCORES[key(eq1, eq2 + 1, eq3, eq4, eq5, eq6)];
  const lower4 = SCORES[key(eq1, eq2, eq3, eq4 + 1, eq5, eq6)];
  const lower5 = SCORES[key(eq1, eq2, eq3, eq4, eq5 + 1, eq6)];
  let lower36;
  if (eq3 === 0 && eq6 === 0) {
    const left = SCORES[key(eq1, eq2, eq3, eq4, eq5, eq6 + 1)];
    const right = SCORES[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6)];
    lower36 = left === undefined ? right : right === undefined ? left : Math.max(left, right);
  } else if (eq3 === 1 && eq6 === 0) lower36 = SCORES[key(eq1, eq2, eq3, eq4, eq5, eq6 + 1)];
  else if (eq6 === 1 && eq3 < 2) lower36 = SCORES[key(eq1, eq2, eq3 + 1, eq4, eq5, eq6)];

  // Distance from the first most-severe vector of the MacroVector that is at least as severe on every metric.
  let d = null;
  search: for (const a of MAX.eq1[eq1]) for (const b of MAX.eq2[eq2]) for (const c of MAX.eq36[eq3][eq6] || []) for (const e of MAX.eq4[eq4]) {
    const top = Object.fromEntries(`${a}/${b}/${c}/${e}`.split('/').map((kv) => kv.split(':')));
    d = Object.fromEntries(Object.keys(LEVEL).map((k) => [k, LEVEL[k][v[k]] - LEVEL[k][top[k]]]));
    if (Object.values(d).every((x) => x >= 0)) break search;
  }
  if (!d) return null;

  const terms = [
    [lower1, d.AV + d.PR + d.UI, DEPTH.eq1[eq1]],
    [lower2, d.AC + d.AT, DEPTH.eq2[eq2]],
    [lower36, d.VC + d.VI + d.VA + d.CR + d.IR + d.AR, DEPTH.eq36[eq3][eq6]],
    [lower4, d.SC + d.SI + d.SA, DEPTH.eq4[eq4]],
    [lower5, 0, 1],
  ].filter(([lower]) => lower !== undefined);
  const mean = terms.length ? terms.reduce((sum, [lower, distance, depth]) => sum + (value - lower) * (distance / depth), 0) / terms.length : 0;
  return Math.round((Math.max(0, Math.min(10, value - mean)) + 1e-6) * 10) / 10;
}
