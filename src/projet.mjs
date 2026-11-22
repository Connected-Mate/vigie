// Reads the dependency files of a project folder and returns the exact package versions it uses.
import { readFile, stat, readdir } from 'node:fs/promises';
import path from 'node:path';

export const MANIFESTS = [
  'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'package.json',
  'poetry.lock', 'uv.lock', 'Pipfile.lock', 'pyproject.toml', 'requirements.txt',
  'Cargo.lock', 'go.mod', 'composer.lock', 'Gemfile.lock', 'gradle.lockfile', 'pom.xml', 'packages.lock.json', 'pubspec.lock',
];
const isRequirements = (name) => /^requirements([-_.][\w.-]+)?\.txt$/i.test(name);
/** True when a file name is one Vigie reads. */
export const isManifest = (name) => MANIFESTS.includes(name) || isRequirements(name);

const MAX_FILE_BYTES = 100 * 1024 * 1024;
const MAX_FILES = 300;
const MAX_DEPTH = 4;
const SKIP_DIRS = new Set(['node_modules', 'vendor', 'dist', 'build', 'out', 'target', 'venv', 'env', '__pycache__', 'bower_components', 'Pods', 'DerivedData', 'coverage', 'tmp']);

const exact = (v) => typeof v === 'string' && /^\d/.test(v);

export function parsePackageLock(text) {
  const j = JSON.parse(text);
  const out = [];
  if (j.packages && typeof j.packages === 'object') {
    for (const [key, v] of Object.entries(j.packages)) {
      const at = key.lastIndexOf('node_modules/');
      // '' is the project itself; keys without node_modules/ are local workspace folders
      if (at < 0 || !v || v.link || !exact(v.version)) continue;
      out.push({ ecosystem: 'npm', name: v.name || key.slice(at + 'node_modules/'.length), version: v.version });
    }
  } else {
    const walk = (deps) => {
      for (const [name, v] of Object.entries(deps || {})) {
        if (!v) continue;
        if (exact(v.version)) out.push({ ecosystem: 'npm', name, version: v.version });
        walk(v.dependencies);
      }
    };
    walk(j.dependencies);
  }
  return out;
}

export function parsePackageJson(text) {
  const j = JSON.parse(text);
  const out = [];
  let ranges = 0;
  for (const group of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [name, range] of Object.entries(j[group] || {})) {
      const m = String(range).match(/^[\^~=v]*(\d+\.\d+\.\d+[^\s|<>]*)$/);
      if (m) out.push({ ecosystem: 'npm', name, version: m[1] });
      else ranges++;
    }
  }
  const notes = ['no lockfile next to it: only the versions written in package.json were checked (lower bound of each range) and indirect dependencies were NOT checked. Run the install to create a lockfile for a complete check.'];
  if (ranges) notes.push(`${ranges} dependenc${ranges > 1 ? 'ies have' : 'y has'} no version number (tag, URL, workspace…) and could not be checked.`);
  return { packages: out, notes };
}

const LOCAL_PROTOCOLS = /^(workspace|link|portal|file|git|github|https?|exec|patch-local):/;

export function parseYarnLock(text) {
  const out = [];
  for (const block of text.split(/\n(?=\S)/)) {
    const header = block.match(/^("?)([^\n]+?)\1?:\s*\n/);
    if (!header || block.startsWith('#') || block.startsWith('__metadata')) continue;
    const version = (block.match(/^\s+version:? "?([^"\n]+)"?/m) || [])[1];
    if (!exact(version) || /-use\.local$/.test(version)) continue;
    const resolution = (block.match(/^\s+resolution: "?([^"\n]+)"?/m) || [])[1];
    // yarn berry: `resolution: "name@npm:1.2.3"`; yarn v1: the header `name@range, name@range2:`
    const spec = (resolution || header[2].split(',')[0]).trim().replace(/^"|"$/g, '');
    const at = spec.indexOf('@', 1);
    if (at < 0) continue;
    let name = spec.slice(0, at);
    const rest = spec.slice(at + 1);
    if (LOCAL_PROTOCOLS.test(rest)) continue;
    const alias = rest.match(/^npm:((?:@[^@/]+\/)?[^@]+)@/); // "foo@npm:bar@1.0.0" installs bar
    if (alias) name = alias[1];
    out.push({ ecosystem: 'npm', name, version });
  }
  return out;
}

export function parsePnpmLock(text) {
  const out = [];
  let inside = false;
  for (const line of text.split('\n')) {
    if (/^\S/.test(line)) {
      inside = /^(packages|snapshots):/.test(line);
      continue;
    }
    if (!inside) continue;
    const m = line.match(/^ {2}(['"]?)(\S.*?)\1:(?:\s.*)?$/);
    if (!m) continue;
    let key = m[2].replace(/^\//, '');
    const paren = key.indexOf('(');
    if (paren > 0) key = key.slice(0, paren); // peer suffix, v6+
    // v6+: name@1.0.0 · v5: name/1.0.0_peer@x
    const hit = key.match(/^((?:@[^/@\s]+\/)?[^/@\s]+)@(\d[^@_\s]*)$/) || key.match(/^((?:@[^/@\s]+\/)?[^/@\s]+)\/(\d[^_/\s]*)(?:_.*)?$/);
    if (hit) out.push({ ecosystem: 'npm', name: hit[1], version: hit[2] });
  }
  return out;
}

export function parseBunLock(text) {
  const out = [];
  const start = text.indexOf('"packages"');
  if (start < 0) return out;
  for (const m of text.slice(start).matchAll(/^\s*"[^"\n]+":\s*\["((?:@[^@"/]+\/)?[^@"/]+)@(\d[^"]*)"/gm)) {
    out.push({ ecosystem: 'npm', name: m[1], version: m[2] });
  }
  return out;
}

const REQ_PIN = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;#,\\]*)\s*(?:[;#].*)?$/;

/** Returns { packages, notes, includes } — `includes` are the `-r other.txt` files to follow. */
export function parseRequirements(text) {
  const packages = [];
  const includes = [];
  let unpinned = 0;
  for (const raw of text.replace(/\\\n/g, ' ').split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const inc = line.match(/^(?:-r|--requirement)[=\s]\s*(\S+)/);
    if (inc) {
      includes.push(inc[1]);
      continue;
    }
    if (line.startsWith('-')) continue;
    const m = line.replace(/\s+--hash=\S+/g, '').match(REQ_PIN);
    if (m) packages.push({ ecosystem: 'PyPI', name: m[1], version: m[2].replace(/\.\*$/, '') });
    else if (/^[A-Za-z0-9]/.test(line) && !/^[a-z]+:\/\/|\.(whl|tar\.gz|zip)\b/i.test(line)) unpinned++;
  }
  const notes = unpinned ? [`${unpinned} requirement${unpinned > 1 ? 's are' : ' is'} not pinned to an exact version (==) and could not be checked.`] : [];
  return { packages, notes, includes };
}

export function parsePyproject(text) {
  const packages = [];
  for (const m of text.matchAll(/["']([A-Za-z0-9][\w.-]*)\s*(?:\[[^\]]*\])?\s*==\s*([0-9][^"'\s;,*]*)\s*(?:;[^"']*)?["']/g)) {
    packages.push({ ecosystem: 'PyPI', name: m[1], version: m[2] });
  }
  return { packages, notes: ['no lockfile next to it: only dependencies pinned with == were checked; ranges and indirect dependencies were NOT checked. Create a lockfile (uv lock, poetry lock) for a complete check.'] };
}

export function parseTomlLock(text, ecosystem) {
  const out = [];
  for (const block of text.split(/^\[\[package\]\]/m).slice(1)) {
    const body = block.split(/^\[\[?(?!package\.)/m)[0];
    const name = (body.match(/^name\s*=\s*"([^"]+)"/m) || [])[1];
    const version = (body.match(/^version\s*=\s*"([^"]+)"/m) || [])[1];
    const source = (body.match(/^source\s*=\s*(.+)$/m) || [])[1] || '';
    // the project itself and its local crates/packages are not published packages
    if (ecosystem === 'crates.io' && !/registry\+/.test(source)) continue;
    if (/\b(editable|virtual|directory|path|git)\s*=/.test(source)) continue;
    if (name && exact(version)) out.push({ ecosystem, name, version });
  }
  return out;
}

export function parsePipfileLock(text) {
  const j = JSON.parse(text);
  const out = [];
  for (const group of ['default', 'develop']) {
    for (const [name, v] of Object.entries(j[group] || {})) {
      const m = String(v?.version || '').match(/^==\s*(\d.*)$/);
      if (m) out.push({ ecosystem: 'PyPI', name, version: m[1] });
    }
  }
  return out;
}

export function parseGoMod(text) {
  const out = [];
  let block = null;
  const add = (line) => {
    const m = line.match(/^([^\s]+\.[^\s]+)\s+v(\d[^\s]*)/);
    if (m) out.push({ ecosystem: 'Go', name: m[1], version: m[2].replace(/\+incompatible$/, '') });
  };
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (!line) continue;
    if (block) {
      if (line === ')') block = null;
      else if (block === 'require') add(line);
      continue;
    }
    const open = line.match(/^(\w+)\s*\($/);
    if (open) block = open[1];
    else if (line.startsWith('require ')) add(line.slice(8).trim());
    else {
      // the Go standard library has its own advisories, keyed by the toolchain version
      const tool = line.match(/^toolchain\s+go(\d+\.\d+\.\d+)$/) || line.match(/^go\s+(\d+\.\d+\.\d+)$/);
      if (tool && !out.some((p) => p.name === 'stdlib')) out.push({ ecosystem: 'Go', name: 'stdlib', version: tool[1] });
    }
  }
  return out;
}

export function parseComposerLock(text) {
  const j = JSON.parse(text);
  return [...(j.packages || []), ...(j['packages-dev'] || [])]
    .map((p) => ({ ecosystem: 'Packagist', name: p?.name, version: String(p?.version || '').replace(/^v/, '') }))
    .filter((p) => p.name && exact(p.version));
}

export function parseGemfileLock(text) {
  const out = [];
  let inGem = false;
  for (const line of text.split('\n')) {
    if (/^\S/.test(line)) inGem = line.trim() === 'GEM';
    const m = inGem && line.match(/^ {4}(\S+) \((\d[^)\s-]*)(?:-[^)]*)?\)$/);
    if (m) out.push({ ecosystem: 'RubyGems', name: m[1], version: m[2] });
  }
  return out;
}

export function parseGradleLock(text) {
  const out = [];
  for (const m of text.matchAll(/^([\w.-]+:[\w.-]+):(\d[^=\s]*)=/gm)) out.push({ ecosystem: 'Maven', name: m[1], version: m[2] });
  return out;
}

export function parsePom(text) {
  const packages = [];
  let unresolved = 0;
  const body = text.replace(/<!--[\s\S]*?-->/g, '');
  for (const m of body.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const pick = (tag) => (m[1].match(new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`)) || [])[1];
    const [g, a, v] = [pick('groupId'), pick('artifactId'), pick('version')];
    if (g && a && exact(v)) packages.push({ ecosystem: 'Maven', name: `${g}:${a}`, version: v });
    else if (g && a) unresolved++;
  }
  const notes = ['pom.xml: only the dependencies written with a literal version were checked; indirect dependencies were NOT checked (Maven resolves them at build time).'];
  if (unresolved) notes.push(`${unresolved} dependenc${unresolved > 1 ? 'ies use' : 'y uses'} a property or an inherited version and could not be checked.`);
  return { packages, notes };
}

export function parseNugetLock(text) {
  const j = JSON.parse(text);
  const out = [];
  for (const framework of Object.values(j.dependencies || {})) {
    for (const [name, v] of Object.entries(framework || {})) {
      if (v?.type !== 'Project' && exact(v?.resolved)) out.push({ ecosystem: 'NuGet', name, version: v.resolved });
    }
  }
  return out;
}

export function parsePubspecLock(text) {
  const out = [];
  for (const block of text.split(/\n(?= {2}\S)/)) {
    const name = (block.match(/^ {2}([\w-]+):\s*$/m) || [])[1];
    const version = (block.match(/^ {4}version: "?([^"\n]+)"?/m) || [])[1];
    if (name && exact(version) && /^ {4}source: hosted/m.test(block)) out.push({ ecosystem: 'Pub', name, version });
  }
  return out;
}

const PARSERS = {
  'package-lock.json': parsePackageLock,
  'npm-shrinkwrap.json': parsePackageLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'yarn.lock': parseYarnLock,
  'bun.lock': parseBunLock,
  'package.json': parsePackageJson,
  'poetry.lock': (t) => parseTomlLock(t, 'PyPI'),
  'uv.lock': (t) => parseTomlLock(t, 'PyPI'),
  'Pipfile.lock': parsePipfileLock,
  'pyproject.toml': parsePyproject,
  'Cargo.lock': (t) => parseTomlLock(t, 'crates.io'),
  'go.mod': parseGoMod,
  'composer.lock': parseComposerLock,
  'Gemfile.lock': parseGemfileLock,
  'gradle.lockfile': parseGradleLock,
  'pom.xml': parsePom,
  'packages.lock.json': parseNugetLock,
  'pubspec.lock': parsePubspecLock,
};

const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock'];
const PY_LOCKS = ['poetry.lock', 'uv.lock', 'Pipfile.lock'];

async function readText(file) {
  const info = await stat(file).catch(() => null);
  if (!info || !info.isFile()) return null;
  if (info.size > MAX_FILE_BYTES) throw new Error('file larger than 100 MB, skipped');
  const text = await readFile(file, 'utf8');
  return text.replace(/^﻿/, '').replace(/\r\n?/g, '\n');
}

/** Folders to read: the root, then sub-folders (monorepos), skipping installed code and hidden folders. */
async function folders(root, recursive) {
  const out = [{ dir: root, names: [] }];
  let manifestCount = 0;
  let truncated = false;
  const walk = async (dir, depth, entry) => {
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : 1));
    for (const e of entries) {
      if (e.isFile() && isManifest(e.name)) {
        if (manifestCount >= MAX_FILES) truncated = true;
        else {
          entry.names.push(e.name);
          manifestCount++;
        }
      }
    }
    if (!recursive || depth >= MAX_DEPTH) return;
    for (const e of entries) {
      // symbolic links are never followed (no loops, no leaving the project)
      if (!e.isDirectory() || e.name.startsWith('.') || SKIP_DIRS.has(e.name)) continue;
      const sub = { dir: path.join(dir, e.name), names: [] };
      await walk(sub.dir, depth + 1, sub);
      if (sub.names.length) out.push(sub);
    }
  };
  await walk(root, 0, out[0]);
  out.sort((a, b) => (a.dir < b.dir ? -1 : 1));
  return { list: out, truncated };
}

/**
 * @returns { root, packages: [{ecosystem,name,version,file}], files: [{file,packages}], notes: [string] }
 */
export async function readProject(dir, { recursive = true } = {}) {
  const root = path.resolve(String(dir));
  const info = await stat(root).catch(() => null);
  if (!info) throw new Error(`Folder not found: ${root}`);
  if (!info.isDirectory()) throw new Error(`Not a folder: ${root}`);

  const packages = [];
  const files = [];
  const notes = [];
  const { list, truncated } = await folders(root, recursive);
  const npmLockedDirs = [];
  const done = new Set();

  const load = async (abs, name, depth = 0) => {
    if (done.has(abs)) return;
    done.add(abs);
    const rel = path.relative(root, abs).split(path.sep).join('/') || name;
    try {
      const text = await readText(abs);
      if (text === null) return;
      const parser = PARSERS[name] || parseRequirements;
      const parsed = parser(text);
      const res = Array.isArray(parsed) ? { packages: parsed } : parsed;
      const found = [...new Map(res.packages.map((p) => [`${p.name}@${p.version}`, p])).values()];
      files.push({ file: rel, packages: found.length });
      for (const p of found) packages.push({ ...p, file: rel });
      for (const n of res.notes || []) notes.push(`${rel}: ${n}`);
      if (NPM_LOCKS.includes(name) && found.length) npmLockedDirs.push(path.dirname(abs));
      for (const inc of res.includes || []) {
        const target = path.resolve(path.dirname(abs), inc);
        if (depth < 3 && (target === root || target.startsWith(root + path.sep))) await load(target, path.basename(target), depth + 1);
      }
    } catch (err) {
      notes.push(`${rel} could not be read (${String(err.message).slice(0, 80)}).`);
    }
  };

  for (const { dir: folder, names } of list) {
    const has = (n) => names.includes(n);
    for (const name of [...MANIFESTS, ...names.filter(isRequirements).sort()]) {
      if (!has(name)) continue;
      // a lockfile in this folder or in a parent (workspaces) is more precise than package.json
      if (name === 'package.json' && npmLockedDirs.some((d) => folder === d || folder.startsWith(d + path.sep))) continue;
      if (name === 'pyproject.toml' && PY_LOCKS.some(has)) continue;
      await load(path.join(folder, name), name);
    }
  }
  if (truncated) notes.push(`More than ${MAX_FILES} dependency files in this folder: only the first ${MAX_FILES} were read. Check sub-folders one by one.`);
  if (!files.length) notes.push(`No dependency file found in ${root} (looked for: ${MANIFESTS.join(', ')}, requirements*.txt).`);
  return { root, packages, files, notes };
}

/** `.vigieignore` in a project: one advisory id (GHSA-…, CVE-…) or `name@version` per line, `#` comments. */
export async function readIgnore(dir) {
  try {
    const text = await readText(path.join(path.resolve(String(dir)), '.vigieignore'));
    if (!text) return [];
    return text.split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean);
  } catch {
    return [];
  }
}
