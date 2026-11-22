// HTTP with timeout, one retry and a time budget + a small disk cache.
// Only public, unauthenticated endpoints are called.
import { mkdir, readFile, writeFile, rename, readdir, stat, unlink, utimes } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

export const VERSION = '1.0.0';
export const cacheDir = () => process.env.VIGIE_CACHE_DIR || path.join(os.homedir(), '.cache', 'vigie');

export const HOUR = 3600 * 1000;
export const DAY = 24 * HOUR;
const MAX_BYTES = 64 * 1024 * 1024;

// ---- time budget: a hook must never hang an agent --------------------------------------------------------
let deadline = 0;
/** After this call, every network request fails fast once `ms` milliseconds have passed. 0 = no limit. */
export function setBudget(ms) {
  deadline = ms > 0 ? Date.now() + ms : 0;
}
export const remaining = () => (deadline ? deadline - Date.now() : Infinity);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export async function http(url, { method = 'GET', body, timeoutMs = 20000, text = false, headers = {}, retries = 1 } = {}) {
  const host = new URL(url).host;
  for (let attempt = 0; ; attempt++) {
    const left = remaining();
    if (left <= 50) throw new Error(`time budget used up before reaching ${host}`);
    let retryable = false;
    try {
      const res = await fetch(url, {
        method,
        body: body ? JSON.stringify(body) : undefined,
        headers: { 'user-agent': `vigie/${VERSION}`, accept: 'application/json, */*', ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
        signal: AbortSignal.timeout(Math.min(timeoutMs, left)),
        redirect: 'follow',
      });
      if (!res.ok) {
        retryable = res.status === 429 || res.status >= 500;
        const err = new Error(`HTTP ${res.status} on ${host}`);
        err.status = res.status;
        throw err;
      }
      if (Number(res.headers.get('content-length') || 0) > MAX_BYTES) throw new Error(`response too large on ${host}`);
      const raw = await res.text();
      if (raw.length > MAX_BYTES) throw new Error(`response too large on ${host}`);
      if (text) return raw;
      try {
        return JSON.parse(raw);
      } catch {
        throw new Error(`unreadable answer from ${host}`);
      }
    } catch (err) {
      const network = err?.status === undefined && !/too large|unreadable/.test(String(err?.message));
      if (attempt >= retries || !(retryable || network) || remaining() < 1500) {
        if (err?.name === 'TimeoutError' || err?.name === 'AbortError') throw new Error(`timeout on ${host}`);
        if (err?.status === undefined && err?.cause) throw new Error(`cannot reach ${host} (${err.cause.code || err.cause.message || 'network error'})`);
        throw err;
      }
      await sleep(400);
    }
  }
}

// ---- disk cache ---------------------------------------------------------------------------------------------
const fileOf = (key) => path.join(cacheDir(), createHash('sha1').update(key).digest('hex') + '.json');
const memory = new Map(); // key -> { at, value }
const inflight = new Map(); // key -> Promise, so concurrent calls share one download

async function readEntry(key) {
  const hit = memory.get(key);
  if (hit) return hit;
  try {
    const entry = JSON.parse(await readFile(fileOf(key), 'utf8'));
    // a truncated or foreign file is treated as "no cache", never trusted
    if (entry && typeof entry.at === 'number' && entry.at <= Date.now() + HOUR && 'value' in entry && entry.value !== undefined) return entry;
  } catch {
    /* no cache yet, or unreadable */
  }
  return null;
}

async function writeEntry(key, entry) {
  memory.set(key, entry);
  if (memory.size > 3000) memory.delete(memory.keys().next().value);
  try {
    await mkdir(cacheDir(), { recursive: true });
    const file = fileOf(key);
    const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    await writeFile(tmp, JSON.stringify(entry));
    await rename(tmp, file); // atomic: a concurrent reader never sees half a file
  } catch {
    /* a read-only or full disk must not break a check */
  }
}

/**
 * Returns { value, stale }. When the source is down and an old copy exists, the old copy is
 * returned with stale=true so the report can say so instead of pretending to be fresh.
 */
export async function cached(key, ttlMs, produce) {
  const old = await readEntry(key);
  if (old && Date.now() - old.at < ttlMs) return { value: old.value, stale: false };
  if (!inflight.has(key)) {
    inflight.set(
      key,
      (async () => {
        try {
          const value = await produce();
          await writeEntry(key, { at: Date.now(), value });
          return { value, stale: false };
        } catch (err) {
          if (old) return { value: old.value, stale: true };
          throw err;
        } finally {
          inflight.delete(key);
        }
      })(),
    );
  }
  return inflight.get(key);
}

/** Small JSON state kept next to the cache (what a hook already reported in a session). */
export async function readState(key) {
  return (await readEntry(`state:${key}`))?.value ?? null;
}
export async function writeState(key, value) {
  await writeEntry(`state:${key}`, { at: Date.now(), value });
}

/** Deletes cache files not touched for 30 days. Runs at most once a day, never throws. */
export async function prune(maxAgeMs = 30 * DAY) {
  try {
    const dir = cacheDir();
    const marker = path.join(dir, '.pruned');
    const last = await stat(marker).catch(() => null);
    if (last && Date.now() - last.mtimeMs < DAY) return 0;
    await mkdir(dir, { recursive: true });
    await writeFile(marker, '');
    await utimes(marker, new Date(), new Date());
    let removed = 0;
    for (const name of await readdir(dir)) {
      if (!/\.(json|tmp)$/.test(name)) continue;
      const file = path.join(dir, name);
      const info = await stat(file).catch(() => null);
      if (info && Date.now() - info.mtimeMs > (name.endsWith('.tmp') ? HOUR : maxAgeMs)) {
        await unlink(file).catch(() => {});
        removed++;
      }
    }
    return removed;
  } catch {
    return 0;
  }
}

/** Runs fn over items with at most `limit` in flight. */
export async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i], i);
      }
    }),
  );
  return out;
}

/** Resolves with fn()'s result, or rejects after `ms` (the work itself is left to finish or be cut by the budget). */
export function within(ms, label, fn) {
  if (!(ms > 0) || ms === Infinity) return fn();
  let timer;
  const limit = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} took more than ${Math.round(ms / 1000)} s`)), ms);
  });
  return Promise.race([fn(), limit]).finally(() => clearTimeout(timer));
}
