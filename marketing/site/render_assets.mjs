// Renders the raster assets of the site from its own drawing (no AI image, no fake screenshot):
//   docs/assets/icon-512.png, og.jpg, og-en.jpg (1200x630), hero.png
// Needs a local preview server on the repo root and an existing Playwright install:
//   python3 -m http.server 8765 --bind 127.0.0.1
//   PLAYWRIGHT_FROM=/path/to/a/project/node_modules/ node marketing/site/render_assets.mjs
import { createRequire } from 'node:module';
const require = createRequire(process.env.PLAYWRIGHT_FROM || import.meta.url);
const { chromium } = require('playwright');
const base = process.env.BASE || 'http://127.0.0.1:8765';
const browser = await chromium.launch();
const shot = async (url, path, width, height, opts = {}) => {
  const ctx = await browser.newContext({ viewport: { width, height }, deviceScaleFactor: opts.dpr || 1, reducedMotion: 'reduce', colorScheme: 'light' });
  const page = await ctx.newPage();
  await page.goto(base + url, { waitUntil: 'load' });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(400);
  const target = opts.sel ? page.locator(opts.sel) : page;
  await target.screenshot({ path, type: path.endsWith('.jpg') ? 'jpeg' : 'png', ...(path.endsWith('.jpg') ? { quality: 86 } : {}), omitBackground: !!opts.transparent });
  await ctx.close();
  console.log('wrote', path);
};
await shot('/docs/assets/icon.svg', 'docs/assets/icon-512.png', 512, 512, { transparent: true });
await shot('/marketing/site/_build/og-fr.html', 'docs/assets/og.jpg', 1200, 630);
await shot('/marketing/site/_build/og-en.html', 'docs/assets/og-en.jpg', 1200, 630);
await shot('/marketing/site/_build/og-fr.html', 'docs/assets/hero.png', 1600, 900, { sel: '.og__scene' }).catch((e) => console.log('hero skipped', e.message));
await browser.close();
