import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { compareVersions, maxVersion } from '../src/versions.mjs';
import { fixedVersion, summarize, normalizeEcosystem } from '../src/providers/osv.mjs';
import { parseFeed, search as certSearch } from '../src/providers/certfr.mjs';
import { search as kevSearch } from '../src/providers/kev.mjs';
import { checkPackages, formatReport, normalizePackages } from '../src/analyse.mjs';
import { parsePackageLock, parsePackageJson, parseRequirements, parseYarnLock, parsePnpmLock, parseTomlLock, parseGoMod, readProject } from '../src/projet.mjs';
import { handle } from '../src/server.mjs';
import { parseInstalls } from '../bin/vigie-hook.mjs';

test('versions', () => {
  assert.equal(compareVersions('4.17.20', '4.17.21'), -1);
  assert.equal(compareVersions('1.10.0', '1.9.9'), 1);
  assert.equal(compareVersions('v2.0', '2.0.0'), 0);
  assert.equal(compareVersions('1.0.0-rc.1', '1.0.0'), -1);
  assert.equal(compareVersions('1.0.0-rc.2', '1.0.0-rc.10'), -1);
  assert.equal(maxVersion(['1.2.3', '1.10.0', '1.9.0']), '1.10.0');
});

const vuln = {
  id: 'GHSA-aaaa-bbbb-cccc',
  aliases: ['CVE-2099-0001'],
  summary: 'Bad thing',
  database_specific: { severity: 'MODERATE' },
  affected: [
    { package: { ecosystem: 'npm', name: 'demo' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.5' }, { introduced: '2.0.0' }, { fixed: '2.3.1' }] }] },
    { package: { ecosystem: 'npm', name: 'other' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '9.9.9' }] }] },
  ],
};

test('osv: fixed version is the one of the range the version sits in', () => {
  assert.equal(fixedVersion(vuln, { ecosystem: 'npm', name: 'demo', version: '1.0.0' }), '1.2.5');
  assert.equal(fixedVersion(vuln, { ecosystem: 'npm', name: 'demo', version: '2.1.0' }), '2.3.1');
  assert.equal(fixedVersion({ ...vuln, affected: [] }, { ecosystem: 'npm', name: 'demo', version: '1.0.0' }), null);
  const s = summarize(vuln, { ecosystem: 'npm', name: 'demo', version: '2.1.0' });
  assert.deepEqual(s.cves, ['CVE-2099-0001']);
  assert.equal(s.severity, 'MEDIUM');
  assert.equal(normalizeEcosystem('pip'), 'PyPI');
  assert.equal(normalizeEcosystem('cobol'), null);
});

test('normalizePackages rejects bad input and dedupes', () => {
  const { packages, skipped } = normalizePackages([
    { ecosystem: 'npm', name: 'a', version: '^1.0.0' },
    { ecosystem: 'NPM', name: 'a', version: '1.0.0' },
    { ecosystem: 'npm', name: 'b', version: 'latest' },
    { ecosystem: 'cobol', name: 'c', version: '1' },
    { ecosystem: 'npm', version: '1' },
    null,
  ]);
  assert.equal(packages.length, 1);
  assert.equal(skipped.length, 4);
});

const fakeProviders = (over = {}) => ({
  osv: { check: async (pkgs) => pkgs.map((p) => (p.name === 'demo' ? [summarize(vuln, p)] : p.name === 'evil' ? [summarize({ id: 'MAL-2099-1', summary: 'Malware' }, p)] : [])) },
  kev: { catalogue: async () => ({ byCve: new Map([['CVE-2099-0001', { added: '2099-01-01', ransomware: true, action: 'Patch' }]]) }) },
  epss: { scores: async () => new Map([['CVE-2099-0001', 0.42]]) },
  certfr: { index: async () => ({ byCve: new Map([['CVE-2099-0001', [{ ref: 'CERTFR-2099-ALE-001', kind: 'alerte', title: 'Alerte', link: 'https://x', closed: null }]]]) }) },
  ...over,
});

test('report: cross-checks sources, prioritizes and says what to do', async () => {
  const r = await checkPackages([{ ecosystem: 'npm', name: 'ok', version: '1.0.0' }, { ecosystem: 'npm', name: 'demo', version: '1.0.0' }, { ecosystem: 'npm', name: 'evil', version: '0.0.1' }], fakeProviders());
  assert.equal(r.verdict, 'vulnerable');
  assert.equal(r.findings.length, 2);
  const demo = r.findings.find((f) => f.package.name === 'demo');
  assert.equal(demo.priority, 0);
  assert.equal(demo.vulnerabilities[0].exploited, true);
  assert.match(demo.action, /Upgrade demo to 1\.2\.5/);
  assert.match(r.findings.find((f) => f.package.name === 'evil').action, /Remove evil immediately/);
  const text = formatReport(r);
  assert.match(text, /ACT NOW/);
  assert.match(text, /exploited in real attacks \(ransomware\)/);
  assert.match(text, /CERT-FR CERTFR-2099-ALE-001/);
  assert.match(text, /exploit probability 42%/);
});

test('report: clean, and never "clean" when the main source is down', async () => {
  const clean = await checkPackages([{ ecosystem: 'npm', name: 'ok', version: '1.0.0' }], fakeProviders());
  assert.equal(clean.verdict, 'clean');
  const down = await checkPackages([{ ecosystem: 'npm', name: 'ok', version: '1.0.0' }], fakeProviders({ osv: { check: async () => { throw new Error('boom'); } } }));
  assert.equal(down.verdict, 'incomplete');
  assert.match(formatReport(down), /Do NOT treat these packages as safe/);
  const empty = await checkPackages([{ ecosystem: 'npm', name: 'x', version: 'latest' }], fakeProviders());
  assert.equal(empty.verdict, 'incomplete');
});

test('report: a secondary source down is reported, the check still concludes', async () => {
  const r = await checkPackages([{ ecosystem: 'npm', name: 'demo', version: '1.0.0' }], fakeProviders({ kev: { catalogue: async () => { throw new Error('timeout'); } } }));
  assert.equal(r.verdict, 'vulnerable');
  assert.equal(r.sources.kev.ok, false);
  assert.match(formatReport(r), /CISA Known Exploited Vulnerabilities: UNAVAILABLE/);
});

test('dependency files', async () => {
  assert.deepEqual(parsePackageLock(JSON.stringify({ packages: { '': { name: 'app' }, 'node_modules/a': { version: '1.0.0' }, 'node_modules/@s/b/node_modules/c': { version: '2.0.0' }, 'node_modules/l': { link: true } } })).map((p) => `${p.name}@${p.version}`), ['a@1.0.0', 'c@2.0.0']);
  assert.deepEqual(parsePackageLock(JSON.stringify({ packages: { 'node_modules/@s/b': { version: '3.0.0' } } }))[0].name, '@s/b');
  assert.deepEqual(parsePackageLock(JSON.stringify({ dependencies: { a: { version: '1.0.0', dependencies: { b: { version: '2.0.0' } } } } })).length, 2);
  assert.deepEqual(parsePackageJson(JSON.stringify({ dependencies: { a: '^1.2.3', b: '*', c: 'github:x/y' }, devDependencies: { d: '2.0.0' } })).map((p) => `${p.name}@${p.version}`), ['a@1.2.3', 'd@2.0.0']);
  assert.deepEqual(parseRequirements('# c\nDjango==3.2.1\nrequests[socks]==2.25.0 ; python_version > "3"\nflask>=1\n-r other.txt\n').map((p) => `${p.name}@${p.version}`), ['Django@3.2.1', 'requests@2.25.0']);
  assert.deepEqual(parseYarnLock('lodash@^4.17.0:\n  version "4.17.20"\n\n"@babel/core@^7.0.0":\n  version "7.1.0"\n').map((p) => `${p.name}@${p.version}`), ['lodash@4.17.20', '@babel/core@7.1.0']);
  assert.deepEqual(parsePnpmLock("lockfileVersion: '9.0'\npackages:\n\n  lodash@4.17.20:\n    resolution: {}\n\n  '@babel/core@7.1.0':\n    resolution: {}\n\n  /old@1.0.0:\n    dev: false\n").map((p) => `${p.name}@${p.version}`), ['lodash@4.17.20', '@babel/core@7.1.0', 'old@1.0.0']);
  assert.deepEqual(parseTomlLock('[[package]]\nname = "serde"\nversion = "1.0.1"\n\n[[package]]\nname = "x"\nversion = "0.2.0"\n', 'crates.io').length, 2);
  assert.deepEqual(parseGoMod('module m\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/text v0.3.0\n\tgithub.com/a/b v1.2.3 // indirect\n)\n').map((p) => `${p.name}@${p.version}`), ['golang.org/x/text@0.3.0', 'github.com/a/b@1.2.3']);

  const dir = await mkdtemp(path.join(os.tmpdir(), 'vigie-test-'));
  try {
    const empty = await readProject(dir);
    assert.equal(empty.packages.length, 0);
    assert.match(empty.notes[0], /No dependency file found/);
    await writeFile(path.join(dir, 'package.json'), JSON.stringify({ dependencies: { a: '^1.0.0' } }));
    assert.match((await readProject(dir)).notes[0], /No lockfile found/);
    await writeFile(path.join(dir, 'package-lock.json'), '{broken');
    assert.match((await readProject(dir)).notes.join(' '), /package-lock\.json could not be read/);
    await assert.rejects(readProject(path.join(dir, 'nope')), /Folder not found/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('CERT-FR feed parsing and keyword search; KEV search', () => {
  const items = parseFeed('<rss><channel><item><title>Vuln dans PostgreSQL &amp; co</title><link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1344/</link><pubDate>Fri, 20 Nov 2026 00:00:00 +0000</pubDate></item><item><title>no ref</title><link>https://x/</link></item></channel></rss>');
  assert.equal(items.length, 1);
  assert.equal(items[0].ref, 'CERTFR-2026-AVI-1344');
  assert.equal(items[0].title, 'Vuln dans PostgreSQL & co');
  const idx = { bulletins: [{ ...items[0], kind: 'avis', products: ['PostgreSQL'], cves: [] }] };
  assert.equal(certSearch(idx, 'postgresql').length, 1);
  assert.equal(certSearch(idx, 'oracle').length, 0);
  assert.equal(certSearch(idx, '  ').length, 0);
  const cat = { entries: [{ cve: 'CVE-1', vendor: 'Apache', product: 'Log4j2', added: '2021-12-10' }] };
  assert.equal(kevSearch(cat, 'apache log4j').length, 1);
  assert.equal(kevSearch(cat, 'nginx').length, 0);
});

test('hook: reads install commands', () => {
  const names = (c) => parseInstalls(c).map((p) => `${p.ecosystem}:${p.name}@${p.version}`);
  assert.deepEqual(names('npm install lodash@4.17.20 --save'), ['npm:lodash@4.17.20']);
  assert.deepEqual(names('cd app && npm i @scope/pkg@1.0.0 left-pad'), ['npm:@scope/pkg@1.0.0', 'npm:left-pad@null']);
  assert.deepEqual(names('pip install "django==3.2.1" -r requirements.txt'), ['PyPI:django@3.2.1']);
  assert.deepEqual(names('uv pip install requests'), ['PyPI:requests@null']);
  assert.deepEqual(names('npm install'), []);
  assert.deepEqual(names('npm install ./local.tgz git+https://x/y.git'), []);
  assert.deepEqual(names('npm run build && ls'), []);
  assert.deepEqual(names('pnpm add -D vitest@1.0.0'), ['npm:vitest@1.0.0']);
});

test('MCP protocol', async () => {
  const init = await handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26' } });
  assert.equal(init.result.protocolVersion, '2025-03-26');
  assert.match(init.result.instructions, /BEFORE adding/);
  assert.equal(await handle({ jsonrpc: '2.0', method: 'notifications/initialized' }), null);
  const list = await handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
  assert.deepEqual(list.result.tools.map((t) => t.name), ['check_packages', 'check_project', 'check_technologies', 'vulnerability_details', 'list_sources']);
  assert.equal((await handle({ jsonrpc: '2.0', id: 3, method: 'nope' })).error.code, -32601);
  assert.equal((await handle({ id: 3 })).error.code, -32600);
  const bad = await handle({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'check_packages', arguments: { packages: [] } } });
  assert.equal(bad.result.isError, true);
  const unknown = await handle({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'zzz' } });
  assert.equal(unknown.result.isError, true);
  const src = await handle({ jsonrpc: '2.0', id: 6, method: 'tools/call', params: { name: 'list_sources' } });
  assert.match(src.result.content[0].text, /CERT-FR/);
});

test('osv: the same flaw published twice is counted once', async () => {
  const { mergeDuplicates } = await import('../src/providers/osv.mjs');
  const merged = mergeDuplicates([
    { id: 'PYSEC-1', cves: ['CVE-1'], severity: 'UNKNOWN', fixedIn: '2.0', summary: '', malicious: false },
    { id: 'GHSA-x', cves: ['CVE-1'], severity: 'HIGH', fixedIn: null, summary: 's', malicious: false },
    { id: 'GHSA-y', cves: [], severity: 'LOW', fixedIn: null, summary: '', malicious: false },
  ]);
  assert.equal(merged.length, 2);
  assert.deepEqual([merged[0].id, merged[0].severity, merged[0].fixedIn], ['GHSA-x', 'HIGH', '2.0']);
});
