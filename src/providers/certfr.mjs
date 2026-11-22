// CERT-FR (ANSSI) — the French government CERT. Alerts (ongoing, serious) and advisories.
// The public feeds only expose the latest bulletins, so this provider covers what is recent or still open.
import { http, cached, pool, HOUR } from '../cache.mjs';

export const meta = {
  id: 'certfr',
  name: 'CERT-FR (ANSSI, French government)',
  url: 'https://www.cert.ssi.gouv.fr',
  covers: 'Latest French government alerts and advisories (recent bulletins only), matched by CVE or by product name.',
};

const BASE = 'https://www.cert.ssi.gouv.fr';

const decode = (s) =>
  s
    .replace(/<!\[CDATA\[(.*?)\]\]>/gs, '$1')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");

export function parseFeed(xml) {
  const items = [];
  for (const m of xml.matchAll(/<item>(.*?)<\/item>/gs)) {
    const pick = (tag) => decode((m[1].match(new RegExp(`<${tag}[^>]*>(.*?)</${tag}>`, 's')) || [])[1] || '').trim();
    const link = pick('link');
    const ref = (link.match(/CERTFR-\d{4}-[A-Z]{3}-\d+/) || [])[0];
    if (!ref) continue;
    items.push({ ref, title: pick('title'), link, date: new Date(pick('pubDate')).toISOString().slice(0, 10) });
  }
  return items;
}

async function bulletin(item) {
  try {
    const { value } = await cached(`certfr:${item.ref}`, 24 * HOUR, async () => {
      const j = await http(`${item.link.replace(/\/?$/, '/')}json/`);
      return {
        cves: (j.cves || []).map((c) => c.name),
        products: [
          ...new Set(
            (j.affected_systems || []).map((a) =>
              [a.product?.vendor?.name, a.product?.name].filter((x) => x && x !== 'N/A').join(' '),
            ),
          ),
        ].filter(Boolean),
        risks: (j.risks || []).map((r) => r.description),
        closed: j.closed_at || null,
      };
    });
    return { ...item, ...value };
  } catch {
    return { ...item, cves: [], products: [], risks: [], closed: null, incomplete: true };
  }
}

export async function index() {
  const { value, stale } = await cached('certfr:index', 6 * HOUR, async () => {
    const feeds = await Promise.all(
      ['alerte', 'avis'].map(async (kind) =>
        parseFeed(await http(`${BASE}/${kind}/feed/`, { text: true })).map((i) => ({ ...i, kind })),
      ),
    );
    const bulletins = await pool(feeds.flat(), 8, bulletin);
    if (!bulletins.length) throw new Error('CERT-FR feed is empty');
    return bulletins;
  });
  const byCve = new Map();
  for (const b of value) for (const c of b.cves) byCve.set(c, [...(byCve.get(c) || []), b]);
  return { bulletins: value, byCve, stale };
}

/** Bulletins whose title or affected products contain every word of the keyword. Open alerts first. */
export function search(idx, keyword, limit = 10) {
  const words = keyword.toLowerCase().split(/\s+/).filter((w) => /[a-zà-ÿ]/.test(w));
  if (!words.length) return [];
  return idx.bulletins
    .filter((b) => {
      const hay = `${b.title} ${b.products.join(' ')}`.toLowerCase();
      return words.every((w) => hay.includes(w));
    })
    .sort((a, b) => {
      const open = (x) => (x.kind === 'alerte' && !x.closed ? 1 : 0);
      return open(b) - open(a) || (a.date < b.date ? 1 : -1);
    })
    .slice(0, limit);
}
