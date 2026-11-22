// CISA KEV — the catalogue of vulnerabilities known to be exploited in real attacks.
import { http, cached, HOUR } from '../cache.mjs';

export const meta = {
  id: 'kev',
  name: 'CISA Known Exploited Vulnerabilities',
  url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
  covers: 'Vulnerabilities proven to be exploited in the wild (any product, open source or commercial).',
};

const FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export async function catalogue() {
  const { value, stale } = await cached('kev', 6 * HOUR, async () => {
    const j = await http(FEED, { timeoutMs: 30000 });
    if (!Array.isArray(j.vulnerabilities) || !j.vulnerabilities.length) throw new Error('CISA KEV catalogue is empty');
    return {
      version: j.catalogVersion,
      entries: (Array.isArray(j.vulnerabilities) ? j.vulnerabilities : []).filter((v) => v?.cveID).map((v) => ({
        cve: v.cveID,
        vendor: String(v.vendorProject || ''),
        product: String(v.product || ''),
        name: String(v.vulnerabilityName || ''),
        added: v.dateAdded,
        ransomware: v.knownRansomwareCampaignUse === 'Known',
        action: String(v.requiredAction || '').slice(0, 220),
      })),
    };
  });
  return { ...value, stale, byCve: new Map(value.entries.map((e) => [e.cve, e])) };
}

/** Entries whose vendor or product contains every word of the keyword. */
export function search(cat, keyword, limit = 10) {
  const words = keyword.toLowerCase().split(/\s+/).filter((w) => /[a-z0-9]/.test(w));
  if (!words.length) return [];
  return cat.entries
    .filter((e) => {
      const hay = `${e.vendor} ${e.product}`.toLowerCase();
      return words.every((w) => hay.includes(w));
    })
    .sort((a, b) => (a.added < b.added ? 1 : -1))
    .slice(0, limit);
}
