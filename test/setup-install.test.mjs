// Offline tests of the install path: `vigie setup` on real folders, as an agent following AGENT-SETUP.md runs it.
// No network is used: the hook is only started on a command that installs nothing.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, cp } from 'node:fs/promises';
import { existsSync, realpathSync } from 'node:fs';
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const { setup, homeMismatch, ROOT } = await import('../src/setup.mjs');
const { cli } = await import('../bin/vigie.mjs');

const HERE = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const made = [];
const tmp = async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'vigie-setup-'));
  made.push(dir);
  return dir;
};
after(() => Promise.all(made.map((d) => rm(d, { recursive: true, force: true }))));

const json = async (file) => JSON.parse(await readFile(file, 'utf8'));
const runCli = async (...argv) => {
  const out = [];
  const err = [];
  const code = await cli(argv, (s) => out.push(s), (s) => err.push(s));
  return { code, out: out.join('\n'), err: err.join('\n') };
};
const sh = (command, { cwd, input = '', env = process.env } = {}) => new Promise((resolve) => {
  const child = spawn(command, { shell: true, cwd, env });
  let out = '';
  let err = '';
  child.stdout.on('data', (d) => (out += d));
  child.stderr.on('data', (d) => (err += d));
  child.on('close', (code) => resolve({ code, out, err }));
  child.stdin.end(input);
});
const withEnv = async (name, value, fn) => {
  const before = process.env[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
  try {
    return await fn();
  } finally {
    if (before === undefined) delete process.env[name];
    else process.env[name] = before;
  }
};

test('setup: a broken settings file stops setup before anything is written', async () => {
  // .claude/settings.json is fine, .mcp.json (read second) is broken: nothing at all may change.
  const dir = await tmp();
  const home = await tmp();
  await mkdir(path.join(dir, '.claude'));
  const settings = '{ "permissions": { "allow": ["Bash(ls:*)"] } }\n';
  await writeFile(path.join(dir, '.claude', 'settings.json'), settings);
  await writeFile(path.join(dir, '.mcp.json'), '{oops');
  await assert.rejects(setup('claude', { dir, home }), /\.mcp\.json is not valid JSON.*will not overwrite/);
  assert.equal(await readFile(path.join(dir, '.claude', 'settings.json'), 'utf8'), settings);
  assert.equal(await readFile(path.join(dir, '.mcp.json'), 'utf8'), '{oops');
  assert.deepEqual((await readdir(dir)).sort(), ['.claude', '.mcp.json']);
  assert.deepEqual(await readdir(path.join(dir, '.claude')), ['settings.json']);

  // Same promise for the other agents, and through the command line (exit 2, a sentence, no stack trace).
  const cursor = await tmp();
  await mkdir(path.join(cursor, '.cursor'));
  await writeFile(path.join(cursor, '.cursor', 'hooks.json'), '[1, 2');
  await assert.rejects(setup('cursor', { dir: cursor, home }), /hooks\.json is not valid JSON/);
  assert.deepEqual(await readdir(path.join(cursor, '.cursor')), ['hooks.json']);
  assert.deepEqual(await readdir(cursor), ['.cursor']);

  const r = await runCli('setup', 'claude', dir);
  assert.equal(r.code, 2);
  assert.match(r.err, /is not valid JSON: fix or move it first/);
  assert.equal(r.out, '');

  // Once the file is repaired, the same command goes through.
  await writeFile(path.join(dir, '.mcp.json'), '{}');
  assert.equal((await runCli('setup', 'claude', dir)).code, 0);
  assert.deepEqual((await json(path.join(dir, '.claude', 'settings.json'))).permissions, { allow: ['Bash(ls:*)'] });
  assert.ok((await json(path.join(dir, '.mcp.json'))).mcpServers.vigie);
});

test('setup: running it twice changes nothing, removing it gives back what was there', async () => {
  const dir = await tmp();
  const home = await tmp();
  const mine = {
    permissions: { allow: ['Bash(ls:*)'] },
    hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo mine' }] }] },
  };
  const rules = '# My project\n\nAlways answer in French.\n';
  await mkdir(path.join(dir, '.claude'));
  await writeFile(path.join(dir, '.claude', 'settings.json'), JSON.stringify(mine, null, 2) + '\n');
  await writeFile(path.join(dir, '.mcp.json'), JSON.stringify({ mcpServers: { other: { command: 'x' } } }, null, 2) + '\n');
  await writeFile(path.join(dir, 'CLAUDE.md'), rules);
  const files = ['.claude/settings.json', '.mcp.json', 'CLAUDE.md'].map((f) => path.join(dir, f));
  const read = () => Promise.all(files.map((f) => readFile(f, 'utf8')));
  const before = await read();

  const first = await setup('claude', { dir, home });
  assert.deepEqual(first.log.map((l) => l.split(/\s+/)[0]), ['updated', 'updated', 'updated']);
  const once = await read();
  const second = await setup('claude', { dir, home });
  assert.deepEqual(second.log.map((l) => l.split(/\s+/)[0]), ['unchanged', 'unchanged', 'unchanged']);
  assert.deepEqual(await read(), once);
  const settings = await json(files[0]);
  assert.equal(settings.hooks.PreToolUse.length, 2); // theirs and ours, once
  assert.equal(settings.hooks.PreToolUse[0].hooks[0].command, 'echo mine');
  assert.ok(once[2].startsWith(rules));

  await setup('claude', { dir, home, remove: true });
  assert.deepEqual(await read(), before); // byte for byte
  assert.deepEqual((await setup('claude', { dir, home, remove: true })).log.map((l) => l.split(/\s+/)[0]), ['unchanged', 'unchanged', 'unchanged']);

  // In a folder that had nothing, removing leaves nothing behind.
  const blank = await tmp();
  await setup('claude', { dir: blank, home });
  await setup('claude', { dir: blank, home, remove: true });
  assert.deepEqual(await readdir(blank), []);
});

test('setup: folders with spaces, accents and quotes — the hook command written still starts', async () => {
  // A copy of Vigie in a folder with a space, set up on a project whose name has spaces, accents and an apostrophe.
  const base = realpathSync(await tmp()); // macOS temp folders sit behind a symlink
  const vigie = path.join(base, 'Mes outils', 'vigie maison');
  await mkdir(path.join(vigie, 'bin'), { recursive: true });
  await cp(path.join(HERE, 'src'), path.join(vigie, 'src'), { recursive: true });
  await cp(path.join(HERE, 'bin'), path.join(vigie, 'bin'), { recursive: true });
  await cp(path.join(HERE, 'package.json'), path.join(vigie, 'package.json'));
  const project = path.join(base, 'Mes projets', "épicerie d'été");
  await mkdir(project, { recursive: true });
  const env = { ...process.env, VIGIE_CACHE_DIR: path.join(base, 'cache') };
  delete env.VIGIE_HOME;

  const done = await sh(`node "${path.join(vigie, 'bin', 'vigie.mjs')}" setup claude`, { cwd: project, env });
  assert.equal(done.code, 0, done.err);
  assert.match(done.out, /Vigie's code is in .*vigie maison/);
  const settings = await json(path.join(project, '.claude', 'settings.json'));
  const command = settings.hooks.PreToolUse[0].hooks[0].command;
  assert.equal(command, `node "${path.join(vigie, 'bin', 'vigie-hook.mjs')}"`);
  assert.deepEqual((await json(path.join(project, '.mcp.json'))).mcpServers.vigie.args, [path.join(vigie, 'src', 'server.mjs')]);

  // The agent hands that string to a shell: it must start the hook (exit 0, silent, on a command that installs nothing).
  const event = JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: 'Bash', cwd: project, tool_input: { command: 'ls' } });
  const hook = await sh(command, { cwd: project, input: event, env });
  assert.equal(hook.code, 0, hook.err);
  assert.equal(hook.err, '');

  // And the MCP server entry starts from that folder too.
  const server = await sh(`node "${path.join(vigie, 'src', 'server.mjs')}"`, {
    cwd: project,
    env,
    input: '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}\n',
  });
  assert.match(server.out, /"name":"vigie"/);

  const gone = await sh(`node "${path.join(vigie, 'bin', 'vigie.mjs')}" setup claude --remove`, { cwd: project, env });
  assert.equal(gone.code, 0, gone.err);
  assert.deepEqual(await readdir(project), []);
});

test('VIGIE_HOME: a folder chosen for Vigie is not silently ignored', async () => {
  const elsewhere = await tmp();
  assert.equal(homeMismatch({}, ROOT), '');
  assert.equal(homeMismatch({ VIGIE_HOME: '  ' }, ROOT), '');
  assert.equal(homeMismatch({ VIGIE_HOME: ROOT }, ROOT), '');
  assert.equal(homeMismatch({ VIGIE_HOME: ROOT + path.sep }, ROOT), '');
  assert.equal(homeMismatch({ VIGIE_HOME: path.join(elsewhere, 'not-there-yet') }, path.join(elsewhere, 'not-there-yet')), '');
  const warning = homeMismatch({ VIGIE_HOME: elsewhere }, ROOT);
  assert.match(warning, /^Warning: VIGIE_HOME is set to /);
  assert.ok(warning.includes(elsewhere) && warning.includes(ROOT));

  // The command line says it where an agent looks: on `--version` (the install check) and on `setup`.
  await withEnv('VIGIE_HOME', elsewhere, async () => {
    const v = await runCli('--version');
    assert.equal(v.code, 0);
    assert.match(v.out, /^\d+\.\d+\.\d+$/);
    assert.match(v.err, /VIGIE_HOME is set to .* but this Vigie runs from /);
    const dir = await tmp();
    const s = await runCli('setup', 'claude', dir);
    assert.equal(s.code, 0);
    assert.match(s.err, /VIGIE_HOME is set to /);
    assert.equal((await runCli('setup', 'claude', dir, '--remove')).err, '');
  });
  for (const value of [undefined, ROOT]) {
    await withEnv('VIGIE_HOME', value, async () => {
      assert.equal((await runCli('--version')).err, '');
      const dir = await tmp();
      const s = await runCli('setup', 'claude', dir);
      assert.equal(s.err, '');
      assert.ok(s.out.includes(`Vigie's code is in ${ROOT}`));
      assert.ok(existsSync(path.join(dir, '.mcp.json')));
    });
  }
});
