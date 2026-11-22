// Reads the dependency files of a project folder and returns the exact package versions it uses.
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';

export const MANIFESTS = [
  'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'package.json',
  'requirements.txt', 'poetry.lock', 'uv.lock', 'Cargo.lock', 'go.mod',
];

const read = async (file) => {
  try {
    return await readFile(file, 'utf8');
  } catch {
    return null;
  }
};

export function parsePackageLock(text) {
  const j = JSON.parse(text);
  const out = [];
  if (j.packages) {
    for (const [key, v] of Object.entries(j.packages)) {
      if (!key || v.link || !v.version) continue;
      const name = v.name || key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
      out.push({ ecosystem: 'npm', name, version: v.version });
    }
  } else {
    const walk = (deps) => {
      for (const [name, v] of Object.entries(deps || {})) {
        if (v.version && /^\d/.test(v.version)) out.push({ ecosystem: 'npm', name, version: v.version });
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
  for (const group of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    for (const [name, range] of Object.entries(j[group] || {})) {
      const m = String(range).match(/^[\^~=v]*(\d+\.\d+\.\d+[^\s|<>]*)$/);
      if (m) out.push({ ecosystem: 'npm', name, version: m[1] });
    }
  }
  return out;
}

export function parseYarnLock(text) {
  const out = [];
  // yarn v1: `name@range:` then `  version "1.2.3"` ; yarn berry: `"name@npm:range":` then `  version: 1.2.3`
  for (const m of text.matchAll(/^"?(@?[^@\s"]+)@[^\n]*:\n\s+version:? "?([^"\n]+)"?/gm)) {
    if (/^\d/.test(m[2])) out.push({ ecosystem: 'npm', name: m[1], version: m[2] });
  }
  return out;
}

export function parsePnpmLock(text) {
  const out = [];
  const start = text.search(/^packages:/m);
  if (start < 0) return out;
  for (const m of text.slice(start).matchAll(/^ {2}['"]?\/?(@?[^@\s'"(]+)[@/](\d[^\s'":(]*)/gm)) {
    out.push({ ecosystem: 'npm', name: m[1], version: m[2] });
  }
  return out;
}

export function parseRequirements(text) {
  const out = [];
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([0-9][^\s;#\\]*)/);
    if (m) out.push({ ecosystem: 'PyPI', name: m[1], version: m[2] });
  }
  return out;
}

export function parseTomlLock(text, ecosystem) {
  const out = [];
  for (const block of text.split(/^\[\[package\]\]/m).slice(1)) {
    const name = (block.match(/^name\s*=\s*"([^"]+)"/m) || [])[1];
    const version = (block.match(/^version\s*=\s*"([^"]+)"/m) || [])[1];
    if (name && version) out.push({ ecosystem, name, version });
  }
  return out;
}

export function parseGoMod(text) {
  const out = [];
  for (const m of text.matchAll(/^\s*(?:require\s+)?([a-z0-9][\w.\-/~]*\.[\w.\-/~]+)\s+v(\d[^\s/]*)/gm)) {
    out.push({ ecosystem: 'Go', name: m[1], version: m[2] });
  }
  return out;
}

const PARSERS = {
  'package-lock.json': parsePackageLock,
  'npm-shrinkwrap.json': parsePackageLock,
  'pnpm-lock.yaml': parsePnpmLock,
  'yarn.lock': parseYarnLock,
  'package.json': parsePackageJson,
  'requirements.txt': parseRequirements,
  'poetry.lock': (t) => parseTomlLock(t, 'PyPI'),
  'uv.lock': (t) => parseTomlLock(t, 'PyPI'),
  'Cargo.lock': (t) => parseTomlLock(t, 'crates.io'),
  'go.mod': parseGoMod,
};

const NPM_LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];

export async function readProject(dir) {
  const root = path.resolve(dir);
  const info = await stat(root).catch(() => null);
  if (!info) throw new Error(`Folder not found: ${root}`);
  if (!info.isDirectory()) throw new Error(`Not a folder: ${root}`);

  const packages = [];
  const files = [];
  const notes = [];
  let npmLocked = false;
  for (const name of MANIFESTS) {
    if (name === 'package.json' && npmLocked) continue; // the lockfile is more precise
    const text = await read(path.join(root, name));
    if (text === null) continue;
    try {
      const found = PARSERS[name](text);
      files.push({ file: name, packages: found.length });
      packages.push(...found);
      if (NPM_LOCKS.includes(name) && found.length) npmLocked = true;
      if (name === 'package.json') {
        notes.push('No lockfile found: only the versions written in package.json were checked (lower bound of each range), and indirect dependencies were NOT checked. Run the install to create a lockfile for a complete check.');
      }
    } catch (err) {
      notes.push(`${name} could not be read (${String(err.message).slice(0, 80)}).`);
    }
  }
  if (!files.length) notes.push(`No dependency file found in ${root} (looked for: ${MANIFESTS.join(', ')}).`);
  return { root, packages, files, notes };
}
