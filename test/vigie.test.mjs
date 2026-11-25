// Offline tests: no network is used. Local HTTP servers stand in for slow or broken sources.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, symlink, utimes } from 'node:fs/promises';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CACHE = mkdtempSync(path.join(os.tmpdir(), 'vigie-cache-'));
process.env.VIGIE_CACHE_DIR = CACHE;
after(() => rm(CACHE, { recursive: true, force: true }));

const { compareVersions, maxVersion, isMajorBump, satisfiesNpm, satisfiesPep440 } = await import('../src/versions.mjs');
const { cvss3Score, severityOfScore } = await import('../src/cvss.mjs');
const { http, cached, prune, setBudget, within, cacheDir } = await import('../src/cache.mjs');
const { fixedVersion, summarize, normalizeEcosystem, severityOf, mergeDuplicates } = await import('../src/providers/osv.mjs');
const { parseFeed, search: certSearch } = await import('../src/providers/certfr.mjs');
const { search: kevSearch } = await import('../src/providers/kev.mjs');
const { checkPackages, checkProject, formatReport, compactReport, normalizePackages, highPriority, checkTechnologies, formatTechnologies } = await import('../src/analyse.mjs');
const P = await import('../src/projet.mjs');
const { handle, vulnerabilityDetails } = await import('../src/server.mjs');
const { parseInstalls, parseCommand, splitCommands, readEvent, run } = await import('../bin/vigie-hook.mjs');
const { cli } = await import('../bin/vigie.mjs');

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const tmp = () => mkdtemp(path.join(os.tmpdir(), 'vigie-test-'));
const listen = (handler) => new Promise((resolve) => {
  const server = createServer(handler);
  server.listen(0, '127.0.0.1', () => resolve({ url: `http://127.0.0.1:${server.address().port}`, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) }));
});

test('versions: semver', () => {
  assert.equal(compareVersions('4.17.20', '4.17.21'), -1);
  assert.equal(compareVersions('1.10.0', '1.9.9'), 1);
  assert.equal(compareVersions('v2.0', '2.0.0'), 0);
  assert.equal(compareVersions('1.0.0-rc.1', '1.0.0'), -1);
  assert.equal(compareVersions('1.0.0-rc.2', '1.0.0-rc.10'), -1);
  assert.equal(compareVersions('1.0.0+build5', '1.0.0'), 0);
  assert.equal(compareVersions('0.0.0-20210101000000-abcdef123456', '0.1.0', 'Go'), -1);
  assert.equal(compareVersions('1.2.3.4', '1.2.3', 'NuGet'), 1);
  assert.equal(compareVersions('garbage', '1.0.0'), -1);
  assert.equal(maxVersion(['1.2.3', '1.10.0', '1.9.0']), '1.10.0');
  assert.equal(maxVersion([]), null);
  assert.equal(isMajorBump('3.25.76', '4.6.6'), true);
  assert.equal(isMajorBump('4.17.20', '4.18.1'), false);
});

test('versions: PyPI, Maven and RubyGems have their own rules', () => {
  const py = (a, b) => compareVersions(a, b, 'PyPI');
  assert.equal(py('1.0.post1', '1.0'), 1); // a post-release comes AFTER the release
  assert.equal(py('1.0.dev1', '1.0a1'), -1);
  assert.equal(py('1.0rc1', '1.0'), -1);
  assert.equal(py('1.0a2', '1.0b1'), -1);
  assert.equal(py('1!1.0', '2.0'), 1); // epoch
  assert.equal(py('2.0.0', '2.0'), 0);
  assert.equal(py('1.0+local', '1.0'), 0);
  const mvn = (a, b) => compareVersions(a, b, 'Maven');
  assert.equal(mvn('1.0-SNAPSHOT', '1.0'), -1);
  assert.equal(mvn('5.3.0.RELEASE', '5.3.0'), 0);
  assert.equal(mvn('1.0-rc1', '1.0-beta2'), 1);
  assert.equal(mvn('1.0.1', '1.0-sp'), 1);
  assert.equal(mvn('32.0.0-jre', '32.0.0-android'), 1);
  assert.equal(mvn('2.15.0', '2.14.1'), 1);
  assert.equal(compareVersions('1.0.0.pre', '1.0.0', 'RubyGems'), -1);
  assert.equal(compareVersions('6.1.7.10', '6.1.7.9', 'RubyGems'), 1);
});

test('versions: npm ranges and PyPI specifiers', () => {
  const yes = ['^1.2.3', '>=1.0.0 <2.0.0', '1.x', '1', '1.2.3 - 1.9.0', '*', '', '<=1', '^2 || ^1', '~1.5', '>= 1.5.0', '1.5.0', '=1.5.0'];
  const no = ['~1.2', '^0.2.3', '>1', '<1.5.0', '^2', '1.5.1'];
  for (const r of yes) assert.equal(satisfiesNpm('1.5.0', r), true, r);
  for (const r of no) assert.equal(satisfiesNpm('1.5.0', r), false, r);
  assert.equal(satisfiesNpm('1.5.0', 'not a range!'), null); // never guesses
  assert.equal(satisfiesNpm('2.0.0-rc.1', '^2.0.0-rc.0'), true);
  assert.equal(satisfiesNpm('2.0.0-rc.1', '^1'), false);
  assert.equal(satisfiesNpm('2.0.0-rc.1', '*'), false);
  assert.equal(satisfiesNpm('0.2.9', '^0.2.3'), true);
  assert.equal(satisfiesNpm('0.3.0', '^0.2.3'), false);
  for (const s of ['>=3.2,<4', '~=3.2', '~=3.2.1', '==3.2.*', '==3.2.5', '']) assert.equal(satisfiesPep440('3.2.5', s), true, s);
  for (const s of ['!=3.2.5', '>3.2.5', '~=3.3', '==3.1.*', '<3']) assert.equal(satisfiesPep440('3.2.5', s), false, s);
  assert.equal(satisfiesPep440('4.0', '~=3.2'), false);
  assert.equal(satisfiesPep440('3.2.5', 'wat'), null);
});

test('cvss: base score from the vector', () => {
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'), 10);
  assert.equal(cvss3Score('CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N'), 4.2);
  assert.equal(cvss3Score('CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'), 7.8);
  assert.equal(cvss3Score('CVSS:4.0/AV:N/AC:L'), null);
  assert.equal(cvss3Score('CVSS:3.1/AV:N'), null);
  assert.equal(cvss3Score(undefined), null);
  assert.deepEqual([9.8, 7.5, 5, 2, 0, null].map(severityOfScore), ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', null, null]);
  assert.equal(severityOf({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }), 'CRITICAL');
  assert.equal(severityOf({ affected: [{ database_specific: { cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H' } }] }), 'HIGH');
  assert.equal(severityOf({ database_specific: { severity: 'MODERATE' } }), 'MEDIUM');
  assert.equal(severityOf({}), 'UNKNOWN');
});

test('cache: corrupt files, concurrent calls, stale copy, pruning', async () => {
  let calls = 0;
  const produce = async () => { calls++; await new Promise((r) => setTimeout(r, 20)); return { n: calls }; };
  // 20 concurrent calls share one download
  const all = await Promise.all(Array.from({ length: 20 }, () => cached('t:concurrent', 60000, produce)));
  assert.equal(calls, 1);
  assert.ok(all.every((r) => r.value.n === 1 && r.stale === false));
  // written atomically: no temporary file left
  assert.equal((await readdir(CACHE)).filter((f) => f.endsWith('.tmp')).length, 0);

  // a corrupt cache file is ignored, not trusted, and replaced
  const { createHash } = await import('node:crypto');
  const fileOf = (k) => path.join(CACHE, createHash('sha1').update(k).digest('hex') + '.json');
  for (const [key, junk] of [['t:junk1', '{"at": 12'], ['t:junk2', '{"value":1}'], ['t:junk3', 'null'], ['t:junk4', '']]) {
    await writeFile(fileOf(key), junk);
    assert.deepEqual(await cached(key, 60000, async () => 'fresh'), { value: 'fresh', stale: false });
    assert.equal(JSON.parse(await readFile(fileOf(key), 'utf8')).value, 'fresh');
  }
  // corrupt file AND source down: the error surfaces (no "undefined" value)
  await writeFile(fileOf('t:junk5'), '{broken');
  await assert.rejects(cached('t:junk5', 60000, async () => { throw new Error('down'); }), /down/);
  // source down with an old good copy: the old copy is used and flagged stale
  await writeFile(fileOf('t:old'), JSON.stringify({ at: Date.now() - 10 * 3600 * 1000, value: 'old' }));
  assert.deepEqual(await cached('t:old', 1000, async () => { throw new Error('down'); }), { value: 'old', stale: true });

  // pruning removes files untouched for 30 days, once a day
  const ancient = path.join(CACHE, 'ancient.json');
  await writeFile(ancient, '{}');
  const past = new Date(Date.now() - 40 * 24 * 3600 * 1000);
  await utimes(ancient, past, past);
  assert.equal(await prune(), 1);
  assert.equal(await prune(), 0);
  assert.equal(cacheDir(), CACHE);
});

test('http: timeout, retry, bad answers and the time budget', async () => {
  let hits = 0;
  const srv = await listen((req, res) => {
    hits++;
    if (req.url === '/hang') return; // never answers
    if (req.url === '/flaky') return hits % 2 ? res.writeHead(503).end() : res.end('{"ok":true}');
    if (req.url === '/html') return res.end('<html>maintenance</html>');
    if (req.url === '/404') return res.writeHead(404).end();
    res.end('{"ok":true}');
  });
  try {
    await assert.rejects(http(`${srv.url}/hang`, { timeoutMs: 150, retries: 0 }), /timeout on 127\.0\.0\.1/);
    hits = 0;
    assert.deepEqual(await http(`${srv.url}/flaky`), { ok: true }); // one retry after a 503
    assert.equal(hits, 2);
    await assert.rejects(http(`${srv.url}/html`), /unreadable answer/);
    hits = 0;
    await assert.rejects(http(`${srv.url}/404`), (e) => e.status === 404);
    assert.equal(hits, 1); // a 404 is not retried
    await assert.rejects(http('http://127.0.0.1:1/x', { retries: 0 }), /cannot reach 127\.0\.0\.1:1/);
    setBudget(300);
    const t = Date.now();
    await assert.rejects(http(`${srv.url}/hang`, { timeoutMs: 20000 }), /timeout|time budget/);
    assert.ok(Date.now() - t < 1500);
    await new Promise((r) => setTimeout(r, 300));
    await assert.rejects(http(`${srv.url}/ok`), /time budget used up/);
    await assert.rejects(within(50, 'slow source', () => new Promise(() => {})), /slow source took more than/);
  } finally {
    setBudget(0);
    await srv.close();
  }
});

const vuln = {
  id: 'GHSA-aaaa-bbbb-cccc',
  aliases: ['CVE-2099-0001'],
  summary: 'Bad thing',
  database_specific: { severity: 'MODERATE' },
  affected: [
    { package: { ecosystem: 'npm', name: 'demo' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.5' }, { introduced: '2.0.0' }, { fixed: '2.3.1' }] }] },
    { package: { ecosystem: 'npm', name: 'other' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }] },
    { package: { ecosystem: 'PyPI', name: 'My_Demo' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.0.post1' }] }] },
  ],
};

test('osv: fixed version is the one of the range the version sits in', () => {
  assert.equal(fixedVersion(vuln, { ecosystem: 'npm', name: 'demo', version: '1.0.0' }), '1.2.5');
  assert.equal(fixedVersion(vuln, { ecosystem: 'npm', name: 'demo', version: '2.1.0' }), '2.3.1');
  assert.equal(fixedVersion(vuln, { ecosystem: 'PyPI', name: 'my-demo', version: '1.0' }), '1.0.post1'); // PyPI names and post-releases
  assert.equal(fixedVersion({ ...vuln, affected: [] }, { ecosystem: 'npm', name: 'demo', version: '1.0.0' }), null);
  const s = summarize(vuln, { ecosystem: 'npm', name: 'demo', version: '2.1.0' });
  assert.deepEqual(s.cves, ['CVE-2099-0001']);
  assert.equal(s.severity, 'MEDIUM');
  assert.equal(normalizeEcosystem('pip'), 'PyPI');
  assert.equal(normalizeEcosystem(' NPM '), 'npm');
  assert.equal(normalizeEcosystem('cobol'), null);
  const merged = mergeDuplicates([
    { id: 'PYSEC-1', cves: ['CVE-1'], severity: 'UNKNOWN', fixedIn: '2.0', summary: '', malicious: false },
    { id: 'GHSA-x', cves: ['CVE-1'], severity: 'HIGH', fixedIn: null, summary: 's', malicious: false },
    { id: 'GHSA-y', cves: [], severity: 'LOW', fixedIn: null, summary: '', malicious: false },
  ]);
  assert.equal(merged.length, 2);
  assert.deepEqual([merged[0].id, merged[0].severity, merged[0].fixedIn], ['GHSA-x', 'HIGH', '2.0']);
});

test('normalizePackages rejects bad input and dedupes', () => {
  const { packages, skipped } = normalizePackages([
    { ecosystem: 'npm', name: 'a', version: '^1.0.0', file: 'x/package-lock.json' },
    { ecosystem: 'NPM', name: 'a', version: '1.0.0', file: 'y/package-lock.json' },
    { ecosystem: 'npm', name: 'b', version: 'latest' },
    { ecosystem: 'cobol', name: 'c', version: '1' },
    { ecosystem: 'npm', version: '1' },
    { ecosystem: 'npm', name: 'd', version: '1.0.0 || 2.0.0' },
    { ecosystem: 'npm', name: 'e e', version: '1.0.0' },
    { ecosystem: 'npm', name: 'é中文', version: '1.0.0' },
    null,
    'text',
    42,
  ]);
  assert.deepEqual(packages.map((p) => p.name), ['a', 'é中文']);
  assert.deepEqual(packages[0].files, ['x/package-lock.json', 'y/package-lock.json']);
  assert.equal(skipped.length, 8);
  assert.deepEqual(normalizePackages('nope'), { packages: [], skipped: [] });
});

const fakeProviders = (over = {}) => ({
  osv: {
    check: async (pkgs) => pkgs.map((p) => (p.name === 'demo' ? [summarize(vuln, p)] : p.name === 'evil' ? [summarize({ id: 'MAL-2099-1', summary: 'Malware' }, p)] : p.name === 'high' ? [summarize({ id: 'GHSA-hhhh-hhhh-hhhh', database_specific: { severity: 'HIGH' }, affected: [{ package: { ecosystem: 'npm', name: 'high' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '2.0.0' }] }] }] }, p)] : [])),
    queryIds: async (pkgs) => pkgs.map((p) => (p.version === '2.0.0' ? [{ id: 'GHSA-zzzz' }] : [])),
  },
  kev: { catalogue: async () => ({ byCve: new Map([['CVE-2099-0001', { added: '2099-01-01', ransomware: true, action: 'Patch' }]]) }) },
  epss: { scores: async () => new Map([['CVE-2099-0001', 0.42]]) },
  certfr: { index: async () => ({ byCve: new Map([['CVE-2099-0001', [{ ref: 'CERTFR-2099-ALE-001', kind: 'alerte', title: 'Alerte', link: 'https://x', closed: null }]]]) }) },
  depsdev: {
    signals: async (pkgs) => new Map(pkgs.filter((p) => p.name === 'old' || p.name === 'new').map((p) => [`${p.ecosystem}|${p.name}|${p.version}`, p.name === 'old' ? { deprecated: true, reason: 'use other', ageDays: 900 } : { deprecated: false, reason: '', ageDays: 0.5 }])),
    defaultVersion: async () => '3.1.0',
  },
  ...over,
});
const pk = (name, version = '1.0.0') => ({ ecosystem: 'npm', name, version });

test('report: cross-checks sources, prioritizes and says what to do', async () => {
  const r = await checkPackages([pk('ok'), pk('demo'), pk('evil', '0.0.1'), pk('high')], fakeProviders());
  assert.equal(r.verdict, 'vulnerable');
  assert.equal(r.findings.length, 3);
  const demo = r.findings.find((f) => f.package.name === 'demo');
  assert.equal(demo.priority, 0);
  assert.equal(demo.vulnerabilities[0].exploited, true);
  assert.match(demo.action, /Upgrade demo to 1\.2\.5 \(fixes 1 of 1; that version has no known vulnerability today\)/);
  assert.match(r.findings.find((f) => f.package.name === 'evil').action, /Remove evil immediately/);
  // the first fixed version (2.0.0) is itself vulnerable: the current release is checked and recommended instead
  assert.match(r.findings.find((f) => f.package.name === 'high').action, /Upgrade high to 3\.1\.0, the current release .*first fixed version 2\.0\.0 still has other known vulnerabilities.*major version change/);
  const text = formatReport(r);
  assert.match(text, /VERDICT: 3 known vulnerabilities in 3 of 4 package version\(s\) — 2 package\(s\) need action NOW, 1 high priority/);
  assert.match(text, /exploited in real attacks \(ransomware\)/);
  assert.match(text, /CERT-FR CERTFR-2099-ALE-001/);
  assert.match(text, /exploit probability 42%/);
  assert.match(text, /MALICIOUS PACKAGE/);
  assert.equal(highPriority(r).length, 3);
  const c = compactReport(r);
  assert.deepEqual([c.verdict, c.vulnerabilities, c.affected, c.high_priority], ['vulnerable', 3, 3, 3]);
});

test('report: recommendation stays honest when it cannot be verified', async () => {
  const p = fakeProviders();
  p.osv.queryIds = async () => { throw new Error('down'); };
  const r = await checkPackages([pk('high')], p);
  assert.match(r.findings[0].action, /Upgrade high to 2\.0\.0 or later \(fixes 1 of 1\)/);
  const q = fakeProviders({ depsdev: { defaultVersion: async () => '2.0.0' } });
  const r2 = await checkPackages([pk('high')], q);
  assert.match(r2.findings[0].action, /then check the version you picked again: 2\.0\.0 itself still has 1 other known vulnerability/);
});

test('report: clean, and never "clean" when the main source is down', async () => {
  const clean = await checkPackages([pk('ok')], fakeProviders());
  assert.equal(clean.verdict, 'clean');
  assert.match(formatReport(clean), /VERDICT: no known vulnerability in the 1 package version/);
  const down = await checkPackages([pk('ok')], fakeProviders({ osv: { check: async () => { throw new Error('boom'); } } }));
  assert.equal(down.verdict, 'incomplete');
  assert.match(formatReport(down), /Do NOT treat these packages as safe/);
  assert.match(formatReport(down), /OSV\.dev \(Google \/ OpenSSF\): UNAVAILABLE \(boom\)/);
  const empty = await checkPackages([{ ecosystem: 'npm', name: 'x', version: 'latest' }], fakeProviders());
  assert.equal(empty.verdict, 'incomplete');
  assert.equal((await checkPackages(undefined, fakeProviders())).verdict, 'incomplete');
});

test('report: a secondary source down or too slow is reported, the check still concludes', async () => {
  const r = await checkPackages([pk('demo')], fakeProviders({ kev: { catalogue: async () => { throw new Error('timeout'); } } }));
  assert.equal(r.verdict, 'vulnerable');
  assert.equal(r.sources.kev.ok, false);
  assert.match(formatReport(r), /CISA Known Exploited Vulnerabilities: UNAVAILABLE/);
  const slow = await checkPackages([pk('ok')], fakeProviders({ certfr: { index: () => new Promise(() => {}) } }), { softTimeoutMs: 40 });
  assert.equal(slow.verdict, 'clean');
  assert.match(slow.sources.certfr.error, /took more than/);
  assert.match(formatReport(slow), /some sources were unavailable/);
  const stale = await checkPackages([pk('ok')], fakeProviders({ kev: { catalogue: async () => ({ byCve: new Map(), stale: true }) } }));
  assert.match(formatReport(stale), /older cached copy used/);
});

test('report: release signals and accepted risks are shown, never silent', async () => {
  const r = await checkPackages([pk('old'), pk('new'), pk('ok')], fakeProviders());
  assert.equal(r.verdict, 'clean');
  assert.deepEqual(r.signals.map((s) => `${s.package.name}:${s.kind}`), ['old:deprecated', 'new:fresh']);
  assert.match(formatReport(r), /Worth knowing \(not vulnerabilities\):\n- old@1\.0\.0: deprecated by its author: use other\n- new@1\.0\.0: published 12 hours ago/);
  // .vigieignore: by advisory id, by CVE, by name@version — but never for a malicious package
  for (const entry of ['ghsa-aaaa-bbbb-cccc', 'CVE-2099-0001', 'demo@1.0.0']) {
    const a = await checkPackages([pk('demo')], fakeProviders(), { ignore: [entry] });
    assert.equal(a.verdict, 'clean', entry);
    assert.match(formatReport(a), /Accepted by \.vigieignore, not counted above \(1\): GHSA-aaaa-bbbb-cccc in demo@1\.0\.0/);
  }
  const mal = await checkPackages([pk('evil')], fakeProviders(), { ignore: ['MAL-2099-1', 'evil@1.0.0'] });
  assert.equal(mal.verdict, 'vulnerable');
});

test('report: a large result stays readable', async () => {
  const many = Array.from({ length: 60 }, (_, i) => pk('high', `1.0.${i}`));
  const r = await checkPackages(many, fakeProviders());
  assert.equal(r.findings.length, 60);
  const text = formatReport(r);
  assert.match(text, /… and 35 more affected package\(s\)/);
  assert.ok(text.length < 12000);
  assert.ok(formatReport(r, { full: true }).length > text.length);
  assert.equal(compactReport(r).findings.length, 50);
});

test('dependency files: one parser per format', () => {
  const names = (list) => list.map((p) => `${p.name}@${p.version}`);
  assert.deepEqual(names(P.parsePackageLock(JSON.stringify({ packages: { '': { name: 'app', version: '1.0.0' }, 'packages/local': { version: '0.1.0' }, 'node_modules/a': { version: '1.0.0' }, 'node_modules/@s/b/node_modules/c': { version: '2.0.0' }, 'node_modules/l': { link: true }, 'node_modules/git': { version: 'git+ssh://x' }, 'node_modules/alias': { name: 'real', version: '3.0.0' } } }))), ['a@1.0.0', 'c@2.0.0', 'real@3.0.0']);
  assert.equal(P.parsePackageLock(JSON.stringify({ packages: { 'node_modules/@s/b': { version: '3.0.0' } } }))[0].name, '@s/b');
  assert.equal(P.parsePackageLock(JSON.stringify({ dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } }, g: { version: 'github:x/y' } } })).length, 2);
  assert.deepEqual(P.parsePackageLock('{}'), []);
  const pj = P.parsePackageJson(JSON.stringify({ dependencies: { a: '^1.2.3', b: '*', c: 'github:x/y' }, devDependencies: { d: '2.0.0' } }));
  assert.deepEqual(names(pj.packages), ['a@1.2.3', 'd@2.0.0']);
  assert.match(pj.notes.join(' '), /indirect dependencies were NOT checked.*2 dependencies have no version number/);

  const req = P.parseRequirements('# c\nDjango==3.2.1\nrequests[socks]==2.25.0 ; python_version > "3"\nflask>=1\n-r other.txt\n--index-url https://x\nurllib3==1.26.5 \\\n    --hash=sha256:aaa \\\n    --hash=sha256:bbb\npkg===1.0\nnumpy\n./local.whl\n');
  assert.deepEqual(names(req.packages), ['Django@3.2.1', 'requests@2.25.0', 'urllib3@1.26.5', 'pkg@1.0']);
  assert.deepEqual(req.includes, ['other.txt']);
  assert.match(req.notes[0], /2 requirements are not pinned/);

  assert.deepEqual(names(P.parseYarnLock('# yarn lockfile v1\n\nlodash@^4.17.0, lodash@^4.17.20:\n  version "4.17.20"\n  resolved "https://x"\n\n"@babel/core@^7.0.0":\n  version "7.1.0"\n\n"alias@npm:real-pkg@^1.0.0":\n  version "1.2.0"\n')), ['lodash@4.17.20', '@babel/core@7.1.0', 'real-pkg@1.2.0']);
  assert.deepEqual(names(P.parseYarnLock('__metadata:\n  version: 8\n\n"@scope/pkg@npm:^1.0.0":\n  version: 1.4.0\n  resolution: "@scope/pkg@npm:1.4.0"\n\n"root@workspace:.":\n  version: 0.0.0-use.local\n  resolution: "root@workspace:."\n\n"typescript@patch:typescript@npm%3A5.0.0#x":\n  version: 5.0.0\n  resolution: "typescript@patch:typescript@npm%3A5.0.0#x::version=5.0.0"\n')), ['@scope/pkg@1.4.0', 'typescript@5.0.0']);

  const pnpm9 = "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      lodash:\n        specifier: ^4\n        version: 4.17.20\n\npackages:\n\n  lodash@4.17.20:\n    resolution: {integrity: x}\n\n  '@babel/core@7.1.0':\n    resolution: {}\n\nsnapshots:\n\n  lodash@4.17.20: {}\n\n  '@babel/core@7.1.0(peer@1.0.0)':\n    dependencies:\n      x: 1.0.0\n";
  assert.deepEqual([...new Set(names(P.parsePnpmLock(pnpm9)))], ['lodash@4.17.20', '@babel/core@7.1.0']);
  assert.deepEqual(names(P.parsePnpmLock("lockfileVersion: 5.4\n\npackages:\n\n  /old/1.0.0:\n    dev: false\n\n  /@s/peer/2.0.0_react@17.0.2:\n    dev: false\n\n  /v6@3.0.0(react@18.0.0):\n    dev: false\n\n  github.com/x/y/abcdef:\n    dev: false\n")), ['old@1.0.0', '@s/peer@2.0.0', 'v6@3.0.0']);
  assert.deepEqual(names(P.parseBunLock('{\n  "lockfileVersion": 1,\n  "workspaces": { "": { "name": "x" } },\n  "packages": {\n    "@types/node": ["@types/node@25.6.0", "", { "dependencies": {} }, "sha512-x"],\n    "left-pad": ["left-pad@1.3.0", "", {}, "sha512-y"],\n    "local": ["local@workspace:pkgs/local"],\n  }\n}\n')), ['@types/node@25.6.0', 'left-pad@1.3.0']);

  assert.deepEqual(names(P.parseTomlLock('version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n\n[[package]]\nname = "my-own-crate"\nversion = "0.2.0"\n', 'crates.io')), ['serde@1.0.1']);
  assert.deepEqual(names(P.parseTomlLock('[[package]]\nname = "me"\nversion = "0.1.0"\nsource = { editable = "." }\n\n[[package]]\nname = "requests"\nversion = "2.25.0"\nsource = { registry = "https://pypi.org/simple" }\n\n[[package]]\nname = "old-poetry"\nversion = "1.0"\n\n[package.dependencies]\nname = "trap"\n', 'PyPI')), ['requests@2.25.0', 'old-poetry@1.0']);
  assert.deepEqual(names(P.parsePipfileLock(JSON.stringify({ default: { django: { version: '==3.2.1' }, local: { path: '.' } }, develop: { pytest: { version: '==7.0.0' } } }))), ['django@3.2.1', 'pytest@7.0.0']);
  assert.deepEqual(names(P.parsePyproject('[project]\ndependencies = [\n  "django==3.2.1",\n  "requests>=2",\n  \'flask[async]==2.0.0 ; python_version > "3.8"\',\n]\n').packages), ['django@3.2.1', 'flask@2.0.0']);

  assert.deepEqual(names(P.parseGoMod('module example.com/m\n\ngo 1.22.1\n\nrequire github.com/solo/dep v1.0.0\n\nrequire (\n\tgolang.org/x/text v0.3.0\n\tgithub.com/a/b v1.2.3 // indirect\n\tgithub.com/old/lib v2.0.0+incompatible\n)\n\nreplace (\n\tgithub.com/a/b v1.2.3 => ../local\n)\n\nexclude github.com/x/y v9.9.9\n')), ['stdlib@1.22.1', 'github.com/solo/dep@1.0.0', 'golang.org/x/text@0.3.0', 'github.com/a/b@1.2.3', 'github.com/old/lib@2.0.0']);
  assert.deepEqual(names(P.parseGoMod('module m\n\ngo 1.22\n\ntoolchain go1.22.5\n')), ['stdlib@1.22.5']);
  assert.deepEqual(names(P.parseComposerLock(JSON.stringify({ packages: [{ name: 'monolog/monolog', version: 'v2.0.0' }, { name: 'dev/branch', version: 'dev-main' }], 'packages-dev': [{ name: 'phpunit/phpunit', version: '9.5.0' }] }))), ['monolog/monolog@2.0.0', 'phpunit/phpunit@9.5.0']);
  assert.deepEqual(names(P.parseGemfileLock('GIT\n  remote: https://x\n  specs:\n    private (1.0.0)\n\nGEM\n  remote: https://rubygems.org/\n  specs:\n    rails (6.0.0)\n      actionpack (= 6.0.0)\n    nokogiri (1.13.0-x86_64-linux)\n\nPLATFORMS\n  ruby\n')), ['rails@6.0.0', 'nokogiri@1.13.0']);
  assert.deepEqual(names(P.parseGradleLock('# comment\ncom.google.guava:guava:31.0-jre=compileClasspath\norg.x:y:1.0.0=runtimeClasspath\nempty=\n')), ['com.google.guava:guava@31.0-jre', 'org.x:y@1.0.0']);
  const pom = P.parsePom('<project><dependencies><!-- <dependency><groupId>no</groupId><artifactId>no</artifactId><version>1</version></dependency> --><dependency>\n<groupId>org.apache.logging.log4j</groupId>\n<artifactId>log4j-core</artifactId>\n<version>2.14.1</version></dependency><dependency><groupId>a</groupId><artifactId>b</artifactId><version>${b.version}</version></dependency></dependencies></project>');
  assert.deepEqual(names(pom.packages), ['org.apache.logging.log4j:log4j-core@2.14.1']);
  assert.match(pom.notes.join(' '), /1 dependency uses a property/);
  assert.deepEqual(names(P.parseNugetLock(JSON.stringify({ version: 1, dependencies: { 'net8.0': { 'Newtonsoft.Json': { type: 'Direct', resolved: '12.0.1' }, MyLib: { type: 'Project' } } } }))), ['Newtonsoft.Json@12.0.1']);
  assert.deepEqual(names(P.parsePubspecLock('packages:\n  http:\n    dependency: "direct main"\n    description:\n      name: http\n    source: hosted\n    version: "0.13.0"\n  flutter:\n    dependency: "direct main"\n    source: sdk\n    version: "0.0.0"\nsdks:\n  dart: ">=3.0.0"\n')), ['http@0.13.0']);
  assert.ok(P.isManifest('requirements-dev.txt') && P.isManifest('uv.lock') && !P.isManifest('readme.txt') && !P.isManifest('requirements.md'));
});

test('project folder: empty, broken, monorepo, Windows line ends, non-ASCII, symlinks', async () => {
  const dir = await tmp();
  try {
    const empty = await P.readProject(dir);
    assert.equal(empty.packages.length, 0);
    assert.match(empty.notes[0], /No dependency file found/);
    await writeFile(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { a: '^1.0.0' } }));
    assert.match((await P.readProject(dir)).notes[0], /package\.json: no lockfile next to it/);
    await writeFile(path.join(dir, 'package-lock.json'), '{broken');
    assert.match((await P.readProject(dir)).notes.join(' '), /package-lock\.json could not be read/);
    await assert.rejects(P.readProject(path.join(dir, 'nope')), /Folder not found/);
    await assert.rejects(P.readProject(path.join(dir, 'package.json')), /Not a folder/);

    // a real lockfile wins over package.json, here with a BOM and Windows line ends
    await writeFile(path.join(dir, 'package-lock.json'), '\uFEFF' + JSON.stringify({ packages: { 'node_modules/a': { version: '1.0.1' } } }, null, 2).replace(/\n/g, '\r\n'));
    await writeFile(path.join(dir, 'yarn.lock'), 'b@^2:\r\n  version "2.0.0"\r\n');
    // monorepo: sub-folders are read, installed code and hidden folders are not, links are not followed
    const sub = path.join(dir, 'services', 'api-é中文');
    await mkdir(sub, { recursive: true });
    await writeFile(path.join(sub, 'package.json'), JSON.stringify({ dependencies: { covered: '1.0.0' } })); // covered by the root lockfile
    await writeFile(path.join(sub, 'requirements.txt'), 'Django==3.2.1\n-r extra/more.txt\n-r ../../../../etc/outside.txt\n');
    await mkdir(path.join(sub, 'extra'));
    await writeFile(path.join(sub, 'extra', 'more.txt'), 'flask==1.0\n');
    await writeFile(path.join(sub, 'requirements-dev.txt'), 'pytest==7.0.0\n');
    await mkdir(path.join(dir, 'node_modules', 'x'), { recursive: true });
    await writeFile(path.join(dir, 'node_modules', 'x', 'package-lock.json'), JSON.stringify({ packages: { 'node_modules/hidden': { version: '9.9.9' } } }));
    await mkdir(path.join(dir, '.venv'));
    await writeFile(path.join(dir, '.venv', 'requirements.txt'), 'hidden==9.9.9\n');
    await symlink(dir, path.join(dir, 'loop'));
    await writeFile(path.join(dir, 'pyproject.toml'), '[project]\ndependencies = ["tomli==2.0.0"]\n');

    const r = await P.readProject(dir);
    assert.deepEqual(r.packages.map((p) => `${p.name}@${p.version}`).sort(), ['Django@3.2.1', 'a@1.0.1', 'b@2.0.0', 'flask@1.0', 'pytest@7.0.0', 'tomli@2.0.0']);
    assert.deepEqual(r.files.map((f) => f.file), ['package-lock.json', 'yarn.lock', 'pyproject.toml', 'services/api-é中文/requirements.txt', 'services/api-é中文/extra/more.txt', 'services/api-é中文/requirements-dev.txt']);
    assert.equal(r.packages.find((p) => p.name === 'Django').file, 'services/api-é中文/requirements.txt');
    assert.deepEqual((await P.readProject(dir, { recursive: false })).files.map((f) => f.file), ['package-lock.json', 'yarn.lock', 'pyproject.toml']);

    await writeFile(path.join(dir, '.vigieignore'), '# accepted with the team on 2026-11-22\nGHSA-aaaa-bbbb-cccc  # no fix yet\n\n');
    assert.deepEqual(await P.readIgnore(dir), ['GHSA-aaaa-bbbb-cccc']);
    assert.deepEqual(await P.readIgnore(sub), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('check_project end to end with fake sources, including .vigieignore', async () => {
  const dir = await tmp();
  try {
    await writeFile(path.join(dir, 'package-lock.json'), JSON.stringify({ packages: { 'node_modules/demo': { version: '1.0.0' }, 'node_modules/ok': { version: '1.0.0' } } }));
    const a = await checkProject(dir, {}, fakeProviders());
    assert.match(a.text, /^Project: .*\n- package-lock\.json: 2 package version\(s\)\n\nVERDICT: 1 known vulnerability in 1 of 2/);
    assert.match(a.text, /## \[ACT NOW\] demo@1\.0\.0 \(npm\) — in package-lock\.json/);
    await writeFile(path.join(dir, '.vigieignore'), 'CVE-2099-0001\n');
    const b = await checkProject(dir, {}, fakeProviders());
    assert.equal(b.report.verdict, 'clean');
    assert.match(b.text, /Accepted by \.vigieignore/);
    const none = await checkProject(await tmp(), {}, fakeProviders());
    assert.match(none.text, /VERDICT: INCOMPLETE — nothing to check in this folder/);
    await rm(none.project.root, { recursive: true, force: true });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CERT-FR feed parsing and keyword search; KEV search', async () => {
  const items = parseFeed('<rss><channel><item><title>Vuln dans PostgreSQL &amp; co &#233;</title><link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1344/</link><pubDate>Fri, 20 Nov 2026 00:00:00 +0000</pubDate></item><item><title>no ref</title><link>https://x/</link></item><item><title>bad date</title><link>https://www.cert.ssi.gouv.fr/alerte/CERTFR-2026-ALE-001/</link><pubDate>soon</pubDate></item></channel></rss>');
  assert.equal(items.length, 2);
  assert.equal(items[0].ref, 'CERTFR-2026-AVI-1344');
  assert.equal(items[0].title, 'Vuln dans PostgreSQL & co é');
  assert.equal(items[1].date, ''); // an unreadable date does not break the feed
  assert.deepEqual(parseFeed('<html>maintenance</html>'), []);
  const idx = { bulletins: [{ ...items[0], kind: 'avis', products: ['PostgreSQL'], cves: [] }] };
  assert.equal(certSearch(idx, 'postgresql').length, 1);
  assert.equal(certSearch(idx, 'oracle').length, 0);
  assert.equal(certSearch(idx, '  ').length, 0);
  const cat = { entries: [{ cve: 'CVE-1', vendor: 'Apache', product: 'Log4j2', added: '2021-12-10' }] };
  assert.equal(kevSearch(cat, 'apache log4j').length, 1);
  assert.equal(kevSearch(cat, 'nginx').length, 0);
  const t = await checkTechnologies(['PostgreSQL', ' ', 'postgresql', 42, null], { kev: { catalogue: async () => cat, search: kevSearch }, certfr: { index: async () => { throw new Error('down'); }, search: certSearch } });
  assert.deepEqual(t.results.map((r) => r.keyword), ['PostgreSQL', 'postgresql', '42']);
  assert.match(formatTechnologies(t), /CERT-FR \(ANSSI, French government\): UNAVAILABLE \(down\)/);
  assert.match(formatTechnologies({ sources: {}, results: [] }), /No keyword given/);
});

test('hook: reads install commands', () => {
  const names = (c) => parseInstalls(c).map((p) => `${p.ecosystem}:${p.name}@${p.version}`);
  assert.deepEqual(names('npm install lodash@4.17.20 --save'), ['npm:lodash@4.17.20']);
  assert.deepEqual(names('cd app && npm i @scope/pkg@1.0.0 left-pad'), ['npm:@scope/pkg@1.0.0', 'npm:left-pad@null']);
  assert.deepEqual(names('pip install "django==3.2.1" -r requirements.txt'), ['PyPI:django@3.2.1']);
  assert.deepEqual(names('uv pip install requests'), ['PyPI:requests@null']);
  assert.deepEqual(names('npm install'), []);
  assert.deepEqual(names('npm install ./local.tgz git+https://x/y.git user/repo'), []);
  assert.equal(parseCommand('npm install --no-audit .', '/tmp/p').project, true); // a path install still changes the project
  assert.deepEqual(names('npm run build && ls'), []);
  assert.deepEqual(names('pnpm add -D vitest@1.0.0'), ['npm:vitest@1.0.0']);
  const specs = (c, cwd = '/tmp/p') => {
    const r = parseCommand(c, cwd);
    return [r.installs.map((p) => `${p.ecosystem}:${p.name}@${p.spec}${p.run ? '!' : ''}`).join(' '), r.project ? r.dir : null];
  };
  // a flag's value is not a package; --prefix moves the project folder
  assert.deepEqual(specs('npm i --prefix sub --registry https://r lodash@^4.17.0'), ['npm:lodash@^4.17.0', path.resolve('/tmp/p', 'sub')]);
  assert.deepEqual(specs('sudo -E pip3 install --index-url https://x "django>=3,<4" flask[async]~=2.0'), ['PyPI:django@>=3,<4 PyPI:flask@~=2.0', '/tmp/p']);
  assert.deepEqual(specs('FOO=1 BAR="a b" python3 -m pip install -U pip'), ['PyPI:pip@', '/tmp/p']);
  assert.deepEqual(specs('poetry add "requests@^2.25" --group dev'), ['PyPI:requests@>=2.25,<3', '/tmp/p']);
  // text that only mentions an install is not an install
  assert.deepEqual(specs('echo "npm install evil" && git commit -m "pip install x" # npm i y'), ['', null]);
  // commands inside a shell -c, after pipes and separators, with cd
  assert.deepEqual(specs('bash -lc "cd x && yarn add react@18"'), ['npm:react@18', '/tmp/p/x']);
  assert.deepEqual(specs('echo a; (npm i a@1.0.0 | tee log) & wait'), ['npm:a@1.0.0', '/tmp/p']);
  assert.deepEqual(specs('npm i lodash@npm:lodash-es@4.17.20'), ['npm:lodash-es@4.17.20', '/tmp/p']);
  // packages that are run without being installed
  assert.deepEqual(specs('npx cowsay@1.5.0 hello --from me'), ['npm:cowsay@1.5.0!', null]);
  assert.deepEqual(specs('npx -y -p typescript@5.0.0 tsc --init'), ['npm:typescript@5.0.0!', null]);
  assert.deepEqual(specs('pnpm dlx create-vite@5 my-app'), ['npm:create-vite@5!', null]);
  assert.deepEqual(specs('uvx ruff check .'), ['PyPI:ruff@!', null]);
  // other ecosystems
  assert.deepEqual(specs('cargo add serde@1.0.100 --features derive'), ['crates.io:serde@1.0.100', '/tmp/p']);
  assert.deepEqual(specs('go get golang.org/x/text@v0.3.0'), ['Go:golang.org/x/text@0.3.0', '/tmp/p']);
  assert.deepEqual(specs('gem install rails -v 6.0.0'), ['RubyGems:rails@6.0.0', '/tmp/p']);
  assert.deepEqual(specs('composer require monolog/monolog:2.0.0'), ['Packagist:monolog/monolog@2.0.0', '/tmp/p']);
  assert.deepEqual(specs('dotnet add package Newtonsoft.Json --version 12.0.1'), ['NuGet:Newtonsoft.Json@12.0.1', '/tmp/p']);
  // installs of the project's own files are checked after they ran
  for (const c of ['npm ci', 'npm install', 'yarn', 'pnpm install --frozen-lockfile', 'pip install -r requirements.txt', 'uv sync', 'npm update']) assert.deepEqual(specs(c), ['', '/tmp/p'], c);
  for (const c of ['npm run build', 'npm test', 'yarn build', 'pip --version', 'python script.py', 'ls', '', 'npm']) assert.deepEqual(specs(c), ['', null], c);
  // Windows paths and odd input
  assert.deepEqual(specs('C:\\tools\\npm.cmd install lodash@1.0.0'), ['npm:lodash@1.0.0', '/tmp/p']);
  assert.deepEqual(specs('npm install é"中文" "unterminated'), ['npm:unterminated@', '/tmp/p']); // odd input is read, never thrown on
  assert.deepEqual(splitCommands('a "b c" \'d;e\' f\\ g && h'), [['a', 'b c', 'd;e', 'f g'], ['h']]);
  assert.deepEqual(parseCommand(undefined).installs, []);
  assert.deepEqual(parseCommand('npm i '.repeat(5000) + 'x@1.0.0').installs.length, 1 + 4999 * 2); // long input does not hang
});

test('hook: understands the event of each agent', () => {
  const shell = (e) => { const r = readEvent(e); return r && [r.kind, r.after, r.command, r.cwd]; };
  assert.deepEqual(shell({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd: '/w', tool_input: { command: 'npm i x' } }), ['shell', false, 'npm i x', '/w']); // Claude Code, Codex
  assert.deepEqual(shell({ hook_event_name: 'PostToolUse', tool_name: 'Bash', cwd: '/w', tool_input: { command: 'npm i' }, tool_response: {} }), ['shell', true, 'npm i', '/w']);
  assert.deepEqual(shell({ hook_event_name: 'BeforeTool', tool_name: 'run_shell_command', cwd: '/w', tool_input: { command: 'npm i x' } }), ['shell', false, 'npm i x', '/w']); // Gemini CLI
  assert.deepEqual(shell({ hook_event_name: 'beforeShellExecution', command: 'npm i x', cwd: '/w' }), ['shell', false, 'npm i x', '/w']); // Cursor
  assert.deepEqual(shell({ toolName: 'bash', toolArgs: '{"command":"npm i x"}', cwd: '/w' }), ['shell', false, 'npm i x', '/w']); // Copilot
  assert.deepEqual(shell({ hook_event_name: 'PreToolUse', tool_name: 'exec', tool_input: { command: 'npm i x' }, cwd: '/w' }), ['shell', false, 'npm i x', '/w']); // Devin
  const edit = readEvent({ hook_event_name: 'PostToolUse', tool_name: 'Write', cwd: '/w', tool_input: { file_path: 'sub/package.json' } });
  assert.deepEqual([edit.kind, edit.file], ['edit', path.resolve('/w', 'sub/package.json')]);
  for (const e of [null, 'x', 42, {}, { tool_name: 'Read', tool_input: { file_path: '/w/package.json' } }, { tool_name: 'Bash', tool_input: {} }, { tool_name: 'Bash', tool_input: { command: 42 } }, { tool_name: 'mcp__x__y', tool_input: { command: 'npm i x' } }]) assert.equal(readEvent(e), null);
});

test('hook: blocks dangerous installs, lets the rest through, says each problem once', async () => {
  const inject = { resolve: async (eco, name, spec) => { if (name === 'ghost') throw Object.assign(new Error('HTTP 404'), { status: 404 }); if (name === 'flaky') throw new Error('timeout'); return spec.replace(/^[\^~=]+/, '') || '1.0.0'; }, tree: async (p) => (p.name === 'wrapper' ? [pk('high'), pk('evil')] : p.name === 'mild' ? [pk('high')] : []), providers: fakeProviders() };
  const pre = (command, extra = {}) => run({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd: os.tmpdir(), session_id: 's', tool_input: { command }, ...extra }, inject);

  const blocked = await pre('npm install demo@1.0.0 ok');
  assert.equal(blocked.code, 2);
  assert.match(blocked.message, /^Vigie blocked this command: 1 package\(s\)[\s\S]*## \[ACT NOW\] demo@1\.0\.0[\s\S]*do not edit \.vigieignore yourself/);
  assert.equal((await pre('npm install ok')).code, 0);
  assert.equal((await pre('npm install ok')).message, undefined);
  assert.equal((await pre('ls -la')).code, 0);
  // pulled-in packages: a malicious one blocks, a merely "high" one is a warning
  const mal = await pre('npm i wrapper');
  assert.equal(mal.code, 2);
  assert.match(mal.message, /evil@1\.0\.0 \(npm\) — pulled in by wrapper@1\.0\.0/);
  assert.doesNotMatch(mal.message, /## \[HIGH\] high@/);
  const warn = await pre('npm i mild');
  assert.equal(warn.code, 0);
  assert.match(warn.context, /pulls in 1 package\(s\) with a high-severity known vulnerability \(high@1\.0\.0\)\. Not blocked/);
  // deprecated: said, not blocked
  assert.match((await pre('npm i old')).context, /old@1\.0\.0 — deprecated by its author/);
  // unknown package: the installer will complain; unreachable registry: said, blocked only in strict mode
  assert.deepEqual(await pre('npm i ghost'), { code: 0, claude: true });
  const un = await pre('npm i flaky');
  assert.equal(un.code, 0);
  assert.match(un.message, /could not check flaky.*Not blocked/);
  process.env.VIGIE_STRICT = '1';
  try {
    assert.equal((await pre('npm i flaky')).code, 2);
    const down = await run({ tool_name: 'Bash', tool_input: { command: 'npm i ok' } }, { ...inject, providers: fakeProviders({ osv: { check: async () => { throw new Error('x'); } } }) });
    assert.equal(down.code, 2);
    assert.match(down.message, /Strict mode: blocked/);
  } finally {
    delete process.env.VIGIE_STRICT;
  }

  const dir = await tmp();
  try {
    await writeFile(path.join(dir, 'package-lock.json'), JSON.stringify({ packages: { 'node_modules/demo': { version: '1.0.0' } } }));
    // accepted in .vigieignore by the user: no longer blocks
    await writeFile(path.join(dir, '.vigieignore'), 'GHSA-aaaa-bbbb-cccc\n');
    assert.equal((await pre('npm install demo@1.0.0', { cwd: dir })).code, 0);
    await rm(path.join(dir, '.vigieignore'));

    const post = (command, session = 'post-1') => run({ hook_event_name: 'PostToolUse', tool_name: 'Bash', cwd: dir, session_id: session, tool_input: { command }, tool_response: {} }, inject);
    const first = await post('npm install');
    assert.equal(first.code, 2);
    assert.match(first.message, /after this install: 1 package\(s\) with a high-priority known vulnerability/);
    assert.equal((await post('npm install')).code, 0); // same session, same finding: not repeated
    assert.equal((await post('npm install', 'post-2')).code, 2); // another session is told
    assert.equal((await post('npm run build')).code, 0);
    const edited = await run({ hook_event_name: 'PostToolUse', tool_name: 'Edit', cwd: dir, session_id: 'post-3', tool_input: { file_path: path.join(dir, 'package-lock.json') } }, inject);
    assert.match(edited.message, /after the edit of package-lock\.json/);
    assert.equal((await run({ hook_event_name: 'PostToolUse', tool_name: 'Edit', cwd: dir, tool_input: { file_path: path.join(dir, 'README.md') } }, inject)).code, 0);
    assert.equal((await run({ hook_event_name: 'PostToolUse', tool_name: 'Write', cwd: dir, tool_input: { file_path: path.join(dir, 'gone', 'package.json') } }, inject).catch((e) => e.message)).match?.(/Folder not found/)?.length, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

const spawnNode = (args, { input = '', env = {} } = {}) => new Promise((resolve) => {
  const child = spawn(process.execPath, args, { env: { ...process.env, ...env }, stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '';
  let err = '';
  const t = Date.now();
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (err += d));
  child.on('close', (code) => resolve({ code, out, err, ms: Date.now() - t }));
  child.stdin.on('error', () => {});
  child.stdin.end(input);
});

test('hook process: never hangs an agent when a database does not answer', async () => {
  const srv = await listen(() => {}); // accepts the connection, never answers
  const dir = await tmp();
  try {
    await writeFile(path.join(dir, 'package-lock.json'), JSON.stringify({ packages: { 'node_modules/a': { version: '1.0.0' } } }));
    const event = JSON.stringify({ hook_event_name: 'PostToolUse', tool_name: 'Bash', cwd: dir, session_id: 'x', tool_input: { command: 'npm ci' } });
    const env = { VIGIE_OSV_API: srv.url, VIGIE_HOOK_BUDGET_MS: '2000', VIGIE_STRICT: '' };
    const open = await spawnNode([path.join(ROOT, 'bin', 'vigie-hook.mjs')], { input: event, env });
    assert.equal(open.code, 0);
    assert.match(open.err, /Vigie could not check the project dependencies .*Not blocked/);
    assert.ok(open.ms < 4500, `took ${open.ms} ms`);
    const closed = await spawnNode([path.join(ROOT, 'bin', 'vigie-hook.mjs')], { input: event, env: { ...env, VIGIE_STRICT: '1' } });
    assert.equal(closed.code, 2);
    assert.match(closed.err, /Strict mode: blocked/);
    // not an event, empty input, unrelated tool: silent, exit 0, immediate
    for (const input of ['', 'not json', '[]', '{"tool_name":"Read","tool_input":{"file_path":"/x"}}', '{"tool_name":"Bash","tool_input":{"command":"ls"}}']) {
      const r = await spawnNode([path.join(ROOT, 'bin', 'vigie-hook.mjs')], { input, env });
      assert.deepEqual([r.code, r.out, r.err], [0, '', ''], input);
    }
  } finally {
    await srv.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('MCP protocol', async () => {
  const init = await handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } });
  assert.equal(init.result.protocolVersion, '2025-03-26');
  assert.equal((await handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '1999-01-01' } })).result.protocolVersion, '2025-11-25');
  assert.match(init.result.instructions, /BEFORE adding/);
  assert.equal(await handle({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
  assert.equal(await handle({ jsonrpc: '2.0', method: 'tools/call', params: { name: 'list_sources' } }), null);
  assert.deepEqual((await handle({ jsonrpc: '2.0', id: 'p', method: 'ping' })).result, {});
  const list = await handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.deepEqual(list.result.tools.map((t) => t.name), ['check_packages', 'check_project', 'check_technologies', 'vulnerability_details', 'list_sources']);
  assert.equal((await handle({ jsonrpc: '2.0', id: 3, method: 'nope' })).error.code, -32601);
  assert.equal((await handle({ id: 3 })).error.code, -32600);
  assert.equal((await handle(null)).error.code, -32600);
  const call = (name, args) => handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name, arguments: args } });
  for (const [name, args] of [['check_packages', { packages: [] }], ['check_packages', { packages: 'lodash' }], ['check_packages', null], ['check_packages', { packages: new Array(2001).fill({}) }], ['check_project', { path: 42 }], ['check_project', { path: '/definitely/not/here' }], ['check_technologies', {}], ['vulnerability_details', { id: 'what is this; rm -rf' }], ['vulnerability_details', {}], ['zzz', {}]]) {
    const res = await call(name, args);
    assert.equal(res.result.isError, true, name);
    assert.match(res.result.content[0].text, /^Vigie could not run this check: .*\. Do not treat the packages as safe\.$/);
  }
  const src = await call('list_sources');
  assert.match(src.result.content[0].text, /CERT-FR[\s\S]*deps\.dev/);
  await assert.rejects(vulnerabilityDetails('../../etc/passwd'), /Expected an id/);
});

test('MCP server process: stdio, parse errors, concurrent calls, clean exit', async () => {
  const lines = [
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}',
    '{"jsonrpc":"2.0","method":"notifications/initialized"}',
    'this is not json',
    '',
    '[{"jsonrpc":"2.0","id":9,"method":"ping"}]',
    ...Array.from({ length: 10 }, (_, i) => JSON.stringify({ jsonrpc: '2.0', id: 100 + i, method: 'tools/call', params: { name: 'list_sources' } })),
    '{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
  ];
  const r = await spawnNode([path.join(ROOT, 'src', 'server.mjs')], { input: lines.join('\r\n') + '\n' });
  assert.equal(r.code, 0);
  assert.equal(r.err, '');
  const out = r.out.trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(out.length, 14);
  assert.equal(out.find((m) => m.id === 1).result.serverInfo.name, 'vigie');
  assert.equal(out.filter((m) => m.error?.code === -32700).length, 1);
  assert.equal(out.filter((m) => m.error?.code === -32600).length, 1);
  assert.equal(out.filter((m) => m.id >= 100 && m.result?.isError === false).length, 10);
  assert.equal(out.find((m) => m.id === 2).result.tools.length, 5);
  const viaCli = await spawnNode([path.join(ROOT, 'bin', 'vigie.mjs'), 'mcp'], { input: lines[0] + '\n' });
  assert.equal(JSON.parse(viaCli.out).result.serverInfo.version, JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8')).version);
});

test('CLI: usage, options and exit codes', async () => {
  const runCli = async (...argv) => { const out = []; const err = []; const code = await cli(argv, (s) => out.push(s), (s) => err.push(s)); return { code, out: out.join('\n'), err: err.join('\n') }; };
  assert.equal((await runCli('--help')).code, 0);
  assert.match((await runCli('--help')).out, /vigie check \[folder\]/);
  assert.match((await runCli('--version')).out, /^\d+\.\d+\.\d+$/);
  assert.equal((await runCli()).code, 2);
  assert.match((await runCli('frobnicate')).err, /Unknown command "frobnicate"/);
  assert.match((await runCli('check', '--wat')).err, /Unknown option --wat/);
  assert.match((await runCli('check', '--fail-on', 'sometimes')).err, /--fail-on expects/);
  assert.match((await runCli('check', '/definitely/not/here')).err, /neither a folder nor a package/);
  assert.match((await runCli('check', 'lodash@4.17.20')).err, /neither a folder nor a package/);
  assert.match((await runCli('check', '.', 'npm:a@1.0.0')).err, /Give either one folder, or only packages/);
  const src = await runCli('sources', '--json');
  assert.equal(JSON.parse(src.out).sources.length, 5);
  const dir = await tmp();
  try {
    const empty = await runCli('check', dir);
    assert.equal(empty.code, 2); // nothing to check is not "all clear"
    assert.match(empty.out, /VERDICT: INCOMPLETE — nothing to check/);
    const json = await runCli('check', dir, '--json');
    assert.equal(JSON.parse(json.out).verdict, 'incomplete');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('package: what is published is what runs', async () => {
  const pkg = JSON.parse(await readFile(path.join(ROOT, 'package.json'), 'utf8'));
  const { VERSION } = await import('../src/cache.mjs');
  assert.equal(pkg.version, VERSION);
  assert.equal(pkg.dependencies, undefined); // zero runtime dependency
  for (const file of Object.values(pkg.bin)) {
    const text = await readFile(path.join(ROOT, file), 'utf8');
    assert.ok(text.startsWith('#!/usr/bin/env node\n'), `${file} has a shebang`);
  }
});

test('setup: writes only its own entries, twice gives the same result, remove puts everything back', async () => {
  const { setup } = await import('../src/setup.mjs');
  const dir = await tmp();
  const home = await tmp();
  const read = async (f) => JSON.parse(await readFile(path.join(dir, f), 'utf8'));
  const exists = (f, base = dir) => readFile(path.join(base, f), 'utf8').then(() => true, () => false);
  try {
    // an existing project: its own hooks, servers and instructions must survive
    await mkdir(path.join(dir, '.claude'));
    const mine = { permissions: { allow: ['Bash(ls:*)'] }, hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'my-own-check' }] }] } };
    await writeFile(path.join(dir, '.claude', 'settings.json'), JSON.stringify(mine));
    await writeFile(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: { other: { command: 'x' } } }));
    await writeFile(path.join(dir, 'CLAUDE.md'), '# My project\nMy rules.\n');

    const first = await setup('claude', { dir, home });
    assert.equal(first.log.length, 3);
    const settings = await read('.claude/settings.json');
    assert.deepEqual(settings.permissions, mine.permissions);
    assert.equal(settings.hooks.PreToolUse.length, 2);
    assert.equal(settings.hooks.PreToolUse[0].hooks[0].command, 'my-own-check');
    assert.match(settings.hooks.PreToolUse[1].hooks[0].command, /^node .*bin\/vigie-hook\.mjs"?$/);
    assert.equal(settings.hooks.PostToolUse[0].matcher, 'Bash|Edit|Write|MultiEdit');
    const mcp = await read('.mcp.json');
    assert.deepEqual(Object.keys(mcp.mcpServers), ['other', 'vigie']);
    assert.match(mcp.mcpServers.vigie.args[0], /src\/server\.mjs$/);
    assert.match(await readFile(path.join(dir, 'CLAUDE.md'), 'utf8'), /^# My project\nMy rules\.\n\n<!-- vigie:start -->\n## Vigie[\s\S]*<!-- vigie:end -->\n$/);

    const again = await setup('claude', { dir, home }); // idempotent
    assert.ok(again.log.every((l) => l.startsWith('unchanged')), again.log.join('|'));
    assert.deepEqual(await read('.claude/settings.json'), settings);

    await setup('claude', { dir, home, remove: true });
    assert.deepEqual(await read('.claude/settings.json'), mine);
    assert.deepEqual(await read('.mcp.json'), { mcpServers: { other: { command: 'x' } } });
    assert.equal(await readFile(path.join(dir, 'CLAUDE.md'), 'utf8'), '# My project\nMy rules.\n');

    // an empty project: files are created, and removed again without leaving empty shells
    const blank = await tmp();
    await setup('claude', { dir: blank, home });
    assert.ok((await exists('.mcp.json', blank)) && (await exists('.claude/settings.json', blank)) && (await exists('CLAUDE.md', blank)));
    await setup('claude', { dir: blank, home, remove: true });
    assert.deepEqual(await readdir(blank), []);
    await rm(blank, { recursive: true, force: true });

    // user scope: hooks in the home settings, the server through the agent's own command
    const user = await setup('claude', { dir, home, user: true });
    assert.match(user.next[0], /^claude mcp add --scope user vigie -- node .*server\.mjs/);
    assert.ok(await exists('.claude/settings.json', home));
    assert.equal(await exists('.mcp.json', home), false);
    assert.match((await setup('claude', { dir, home, user: true, remove: true })).next[0], /claude mcp remove --scope user vigie/);
    assert.deepEqual(await readdir(home), []);

    // a broken settings file is never overwritten
    await writeFile(path.join(dir, '.claude', 'settings.json'), '{ "hooks": ');
    await assert.rejects(setup('claude', { dir, home }), /is not valid JSON.*will not overwrite/);
    assert.equal(await readFile(path.join(dir, '.claude', 'settings.json'), 'utf8'), '{ "hooks": ');
    await assert.rejects(setup('emacs', { dir, home }), /Unknown agent "emacs"/);

    // Gemini CLI and Cursor formats
    const g = await tmp();
    await setup('gemini', { dir: g, home });
    const gs = JSON.parse(await readFile(path.join(g, '.gemini', 'settings.json'), 'utf8'));
    assert.deepEqual([gs.mcpServers.vigie.command, gs.hooks.BeforeTool[0].matcher, gs.hooks.BeforeTool[0].hooks[0].timeout], ['node', 'run_shell_command', 30000]);
    await setup('cursor', { dir: g, home });
    const cm = JSON.parse(await readFile(path.join(g, '.cursor', 'mcp.json'), 'utf8'));
    const ch = JSON.parse(await readFile(path.join(g, '.cursor', 'hooks.json'), 'utf8'));
    assert.deepEqual([cm.mcpServers.vigie.type, ch.version, ch.hooks.beforeShellExecution.length], ['stdio', 1, 1]);
    await setup('gemini', { dir: g, home, remove: true });
    await setup('cursor', { dir: g, home, remove: true });
    assert.deepEqual(await readdir(g), []);
    await rm(g, { recursive: true, force: true });
  } finally {
    await rm(dir, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});
