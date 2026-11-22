#!/usr/bin/env node
// Renders the Vigie film from film.html, frame by frame, with the Playwright Chromium already on this Mac
// and the ffmpeg binary of the local "ffmpeg-static" dependency (nothing global).
//   node build.cjs                      everything (FR + EN, 16x9 + 9x16, posters, captions, transcripts)
//   node build.cjs --stills 3,14,26     look at frames first: JPGs in out/stills (add --lang fr --format 9x16)
//   node build.cjs --only text          captions + transcripts only
const { spawn } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const { pathToFileURL } = require('node:url')
const ffmpeg = require('ffmpeg-static')
const { chromium } = require('playwright-core')
const COPY = require('./copy.js')

const here = __dirname
const OUT = path.join(here, 'out'), DEST = path.join(here, '..', 'docs', 'video')
const arg = (k, d) => { const i = process.argv.indexOf('--' + k); return i > 0 ? process.argv[i + 1] : d }
const FPS = 30
const SIZE = { '16x9': [1920, 1080], '9x16': [1080, 1920] }
const POSTER_T = 43.5

const pw = path.join(os.homedir(), 'Library/Caches/ms-playwright')
const chromeDir = fs.readdirSync(pw).filter((d) => /^chromium-\d+$/.test(d)).sort().pop()
const executablePath = path.join(pw, chromeDir, 'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing')

async function open(lang, format) {
  const [W, H] = SIZE[format]
  const browser = await chromium.launch({ executablePath, headless: true, args: ['--force-color-profile=srgb', '--disable-lcd-text'] })
  const page = await browser.newPage({ viewport: { width: W, height: H }, deviceScaleFactor: 1 })
  page.on('pageerror', (e) => { console.error('PAGE ERROR', e.message); process.exitCode = 1 })
  await page.goto(pathToFileURL(path.join(here, 'film.html')).href + `?lang=${lang}&format=${format}`)
  await page.evaluate(() => document.fonts.ready)
  return { browser, page, W, H }
}
const run = (args) => new Promise((res, rej) => { const p = spawn(ffmpeg, ['-hide_banner', '-loglevel', 'error', '-y', ...args], { stdio: ['ignore', 'inherit', 'inherit'] }); p.on('close', (c) => c === 0 ? res() : rej(new Error('ffmpeg exit ' + c))) })

async function stills(lang, format, times) {
  const dir = path.join(OUT, 'stills'); fs.mkdirSync(dir, { recursive: true })
  const { browser, page } = await open(lang, format)
  for (const t of times) {
    await page.evaluate((x) => window.__render(x), t)
    await page.screenshot({ path: path.join(dir, `${lang}-${format}-${t.toFixed(1).padStart(4, '0')}.jpg`), type: 'jpeg', quality: 80 })
  }
  await browser.close()
}

async function film(lang, format) {
  const { browser, page, W, H } = await open(lang, format)
  const name = `vigie-${lang}${format === '9x16' ? '-9x16' : ''}`
  const mp4 = path.join(DEST, name + '.mp4')
  const ff = spawn(ffmpeg, ['-hide_banner', '-loglevel', 'error', '-y', '-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'png', '-i', '-',
    '-vf', 'scale=in_range=full:out_range=tv:out_color_matrix=bt709,format=yuv420p', '-c:v', 'libx264', '-preset', 'slow', '-crf', '24',
    '-colorspace', 'bt709', '-color_primaries', 'bt709', '-color_trc', 'bt709', '-color_range', 'tv', '-movflags', '+faststart', '-an', mp4], { stdio: ['pipe', 'inherit', 'inherit'] })
  const closed = new Promise((r) => ff.on('close', r))
  const n = Math.round(COPY.duration * FPS)
  for (let f = 0; f < n; f++) {
    await page.evaluate((x) => window.__render(x), f / FPS)
    const buf = await page.screenshot({ type: 'png', clip: { x: 0, y: 0, width: W, height: H } })
    if (!ff.stdin.write(buf)) await new Promise((r) => ff.stdin.once('drain', r))
    if (f % 300 === 0) console.log(`  ${name}: ${f}/${n}`)
  }
  ff.stdin.end()
  if (await closed !== 0) throw new Error('ffmpeg failed for ' + name)
  if (format === '16x9') {
    await page.evaluate((x) => window.__render(x), POSTER_T)
    await page.screenshot({ path: path.join(DEST, `poster-${lang}.jpg`), type: 'jpeg', quality: 78 })
    await run(['-i', mp4, '-c:v', 'libvpx-vp9', '-crf', '34', '-b:v', '0', '-row-mt', '1', '-an', path.join(DEST, name + '.webm')])
  }
  await browser.close()
  console.log('done', name)
}

const stamp = (s) => { const m = Math.floor(s / 60), r = (s - m * 60).toFixed(3).padStart(6, '0'); return `00:${String(m).padStart(2, '0')}:${r}` }
function text(lang) {
  const L = lang === 'fr'
  const cues = COPY.beats.map((b) => ({ from: b.from, to: b.to, said: b[lang], pic: b.pic[lang] }))
  const e = COPY.end
  cues.push({ from: e.from, to: e.to, said: `${e.name}. ${e.promise[lang]} ${e.tags[lang].join(', ')}.`, pic: `${e.pic[lang]} ${e.sources}. ${e.limit[lang]}` })
  const vtt = 'WEBVTT\n\n' + cues.map((c, i) => `${i + 1}\n${stamp(c.from)} --> ${stamp(c.to)}\n${c.said}\n[${c.pic}]\n`).join('\n')
  fs.writeFileSync(path.join(DEST, `vigie-${lang}.vtt`), vtt)
  const shown = COPY.report.filter((l) => l.s).map((l) => (l.k === 'cmd' ? '$ ' : '') + l.s).join('\n')
  const head = L
    ? `Vigie, film de présentation (${COPY.duration} secondes, sans son)\nTranscription : le texte affiché, et entre crochets ce que montre l'image.\n`
    : `Vigie, presentation film (${COPY.duration} seconds, silent)\nTranscript: the on-screen text, and in brackets what the picture shows.\n`
  const rep = L
    ? `\nTexte du rapport affiché de 0:21 à 0:34 (sortie réelle de Vigie, en anglais ; « … » = lignes non montrées) :\n`
    : `\nReport text shown from 0:21 to 0:34 (real Vigie output; "…" = lines not shown):\n`
  fs.writeFileSync(path.join(DEST, `transcript-${lang}.txt`), head + '\n' + cues.map((c) => `${stamp(c.from).slice(4, 8)}  ${c.said}\n      [${c.pic}]`).join('\n') + '\n' + rep + shown + '\n')
}

;(async () => {
  fs.mkdirSync(DEST, { recursive: true })
  const langs = arg('lang') ? [arg('lang')] : ['fr', 'en']
  const formats = arg('format') ? [arg('format')] : ['16x9', '9x16']
  if (arg('stills')) { for (const l of langs) for (const f of formats) await stills(l, f, arg('stills').split(',').map(Number)); return }
  for (const l of ['fr', 'en']) text(l)
  if (arg('only') === 'text') return
  for (const l of langs) for (const f of formats) await film(l, f) // one render at a time
})().catch((e) => { console.error(e); process.exit(1) })
