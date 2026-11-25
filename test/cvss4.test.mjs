// CVSS 4.0 scoring. Expected scores come from the reference calculator of the specification
// (https://www.first.org/cvss/calculator/4-0). Offline.
import test from 'node:test';
import assert from 'node:assert/strict';

const { cvss4Score } = await import('../src/cvss4.mjs');
const { severityOf } = await import('../src/providers/osv.mjs');

const B = 'CVSS:4.0/';

test('cvss 4: score from the vector', () => {
  const cases = {
    'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H': 10,
    'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N': 9.3,
    'AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N': 7.3,
    'AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N': 5.3,
    'AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N': 2.3,
    'AV:P/AC:H/AT:P/PR:H/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N': 1,
    // no impact at all
    'AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N': 0,
    // threat metric: no known exploit lowers the score, proof of concept too
    'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U': 8.1,
    'AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:P': 2.1,
    // environmental metric: safety impact raises it
    'AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/MSI:S': 8.9,
  };
  for (const [vector, score] of Object.entries(cases)) assert.equal(cvss4Score(B + vector), score, vector);
});

test('cvss 4: supplemental metrics and "not defined" values do not change the score', () => {
  const base = 'AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
  assert.equal(cvss4Score(`${B}${base}/E:X/CR:X/MAV:X/S:P/AU:Y/R:I/V:C/RE:H/U:Amber`), 9.3);
});

test('cvss 4: an incomplete or invalid vector is not guessed', () => {
  for (const bad of [
    undefined,
    '',
    'CVSS:4.0',
    'CVSS:4.0/AV:N/AC:L',
    'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N', // SA missing
    'CVSS:4.0/AV:Z/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', // unknown value
    'CVSS:4.0/AV:N/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', // twice
    'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/XX:Y', // unknown metric
    'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'CVSS:4.0/__proto__:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
  ]) assert.equal(cvss4Score(bad), null, String(bad));
});

test('cvss 4: an advisory with only a CVSS 4 vector gets a severity instead of UNKNOWN', () => {
  const v4 = (score) => ({ severity: [{ type: 'CVSS_V4', score }] });
  assert.equal(severityOf(v4(`${B}AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`)), 'CRITICAL');
  assert.equal(severityOf(v4(`${B}AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`)), 'HIGH');
  assert.equal(severityOf(v4(`${B}AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N`)), 'MEDIUM');
  assert.equal(severityOf(v4(`${B}AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`)), 'LOW');
  // the vector can also sit on the affected package
  assert.equal(severityOf({ affected: [{ severity: [{ type: 'CVSS_V4', score: `${B}AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` }] }] }), 'CRITICAL');
  // the severity word of the advisory still wins
  assert.equal(severityOf({ database_specific: { severity: 'LOW' }, ...v4(`${B}AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`) }), 'LOW');
  // CVSS 3 and CVSS 4 on the same advisory: the highest counts
  assert.equal(severityOf({ severity: [
    { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N' },
    { type: 'CVSS_V4', score: `${B}AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` },
  ] }), 'CRITICAL');
  // still honest when nothing can be computed
  assert.equal(severityOf(v4('CVSS:4.0/AV:N')), 'UNKNOWN');
  assert.equal(severityOf(v4(`${B}AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N`)), 'UNKNOWN');
});
