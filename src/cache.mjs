// HTTP with timeout + a small disk cache. Only public, unauthenticated endpoints are called.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';

export const cacheDir = () => process.env.VIGIE_CACHE_DIR || path.join(os.homedir(), '.cache', 'vigie');

export const HOUR = 3600 * 1000;

export async function http(url, { method = 'GET', body, timeoutMs = 20000, text = false } = {}) {
  const res = await fetch(url, {
    method,
    body: body ? JSON.stringify(body) : undefined,
    headers: { 'content-type': 'application/json', 'user-agent': 'vigie-mcp' },
    signal: AbortSignal.timeout(timeoutMs),
    redirect: 'follow',
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} on ${new URL(url).host}`);
  return text ? res.text() : res.json();
}

/**
 * Returns { value, stale }. When the source is down and an old copy exists, the old copy is
 * returned with stale=true so the report can say so instead of pretending to be fresh.
 */
export async function cached(key, ttlMs, produce) {
  const file = path.join(cacheDir(), createHash('sha1').update(key).digest('hex') + '.json');
  let old = null;
  try {
    old = JSON.parse(await readFile(file, 'utf8'));
    if (Date.now() - old.at < ttlMs) return { value: old.value, stale: false };
  } catch {
    /* no cache yet, or unreadable */
  }
  try {
    const value = await produce();
    try {
      await mkdir(cacheDir(), { recursive: true });
      await writeFile(file, JSON.stringify({ at: Date.now(), value }));
    } catch {
      /* a read-only disk must not break a check */
    }
    return { value, stale: false };
  } catch (err) {
    if (old) return { value: old.value, stale: true };
    throw err;
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
