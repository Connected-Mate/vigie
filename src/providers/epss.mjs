// EPSS (FIRST.org) — probability that a CVE gets exploited in the next 30 days.
import { http } from '../cache.mjs';

export const meta = {
  id: 'epss',
  name: 'EPSS (FIRST.org)',
  url: 'https://www.first.org/epss/',
  covers: 'A daily score (0 to 1) estimating how likely each CVE is to be exploited soon.',
};

/** Map cve -> probability (number between 0 and 1). */
export async function scores(cves) {
  const out = new Map();
  const ids = cves.filter((c) => /^CVE-\d{4}-\d+$/.test(c));
  for (let i = 0; i < ids.length; i += 80) {
    const j = await http(`https://api.first.org/data/v1/epss?cve=${ids.slice(i, i + 80).join(',')}`, { timeoutMs: 15000 });
    for (const d of j.data || []) if (d?.cve && Number.isFinite(Number(d.epss))) out.set(d.cve, Number(d.epss));
  }
  return out;
}
