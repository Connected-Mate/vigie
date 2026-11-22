// Every word shown in the film, both languages, with its timing (seconds).
// Loaded by film.html (window.COPY) and by build.cjs (captions + transcripts).
// The REPORT lines are copied verbatim from a real run of Vigie 1.0 (22/11/2026) of:
//   echo '{"tool_name":"Bash","tool_input":{"command":"npm install lodash@4.17.20"}}' | node bin/vigie-hook.mjs
// "…" marks lines left out of the real report (three more findings, URLs, the limits paragraph, the closing instruction).
const COPY = {
  duration: 47,
  beats: [
    { id: 'forest', from: 0.8, to: 5.2,
      fr: 'Ton code est une forêt.', en: 'Your code is a forest.',
      pic: { fr: 'Une forêt de sapins à l\'aube, une tour de guet sur la colline.', en: 'A pine forest at dawn, a lookout tower on the hill.' } },
    { id: 'plant', from: 5.8, to: 11.2,
      fr: 'Tes agents y plantent vite. Chaque paquet est un arbre.', en: 'Your agents plant fast. Every package is a tree.',
      pic: { fr: 'Des arbres poussent un à un au premier plan, chacun avec un nom de paquet.', en: 'Trees pop up one by one in the foreground, each with a package name.' } },
    { id: 'smoke', from: 11.8, to: 16.6,
      fr: 'À l\'horizon, une fine fumée : une faille connue.', en: 'On the horizon, a thin smoke: a known vulnerability.',
      pic: { fr: 'Un mince filet de fumée monte derrière la crête la plus lointaine.', en: 'A thin thread of smoke rises behind the farthest ridge.' } },
    { id: 'lookout', from: 17.0, to: 21.2,
      fr: 'Personne ne regarde. La vigie, si.', en: 'Nobody is looking. The lookout is.',
      pic: { fr: 'Le faisceau de la tour de guet se pose sur la fumée.', en: 'The beam of the lookout tower lands on the smoke.' } },
    { id: 'blocked', from: 21.8, to: 27.6,
      fr: 'Installation bloquée, avant qu\'elle n\'arrive.', en: 'Install blocked, before it lands.',
      pic: { fr: 'Le vrai rapport de Vigie s\'affiche : installation de lodash 4.17.20 bloquée, 4 failles connues.', en: 'The real Vigie report appears: install of lodash 4.17.20 blocked, 4 known vulnerabilities.' } },
    { id: 'todo', from: 27.9, to: 34.2,
      fr: 'Le rapport dit à ton agent quoi faire.', en: 'The report tells your agent what to do.',
      pic: { fr: 'La ligne « What to do: Upgrade lodash to 4.18.1 » est mise en avant ; les cinq sources répondent ok.', en: 'The line "What to do: Upgrade lodash to 4.18.1" is highlighted; the five sources answer ok.' } },
    { id: 'safe', from: 34.8, to: 39.6,
      fr: 'L\'agent corrige. La forêt reste sauve.', en: 'The agent fixes it. The forest stays safe.',
      pic: { fr: 'L\'arbre lodash 4.18.1 est planté ; le jour se lève, la tour continue de veiller.', en: 'The lodash 4.18.1 tree is planted; day breaks, the tower keeps watching.' } },
  ],
  end: { from: 40.2, to: 47,
    name: 'Vigie',
    promise: { fr: 'Ton agent vérifie les failles connues, à chaque fois.', en: 'Your agent checks known vulnerabilities, every time.' },
    tags: { fr: ['Gratuit', 'Open source (MIT)', 'Sans compte'], en: ['Free', 'Open source (MIT)', 'No account'] },
    sources: 'OSV.dev · CISA KEV · EPSS · CERT-FR · deps.dev',
    limit: { fr: 'Failles publiques des paquets publiés uniquement.', en: 'Publicly known vulnerabilities in published packages only.' },
    pic: { fr: 'La forêt au matin, le nom Vigie.', en: 'The forest in the morning, the name Vigie.' } },
  panelTitle: { fr: 'Sortie réelle de Vigie', en: 'Real Vigie output' },
  // t = second at which the line appears. k = style key.
  report: [
    { t: 21.8, k: 'cmd', s: 'npm install lodash@4.17.20' },
    { t: 23.2, k: 'block', s: 'Vigie blocked this command: 1 package(s) it would install have a high-priority known vulnerability.' },
    { t: 24.2, k: 'gap' },
    { t: 24.2, k: 'strong', s: 'VERDICT: 4 known vulnerabilities in 1 of 1 package version(s) — 1 high priority.' },
    { t: 25.1, k: 'gap' },
    { t: 25.1, k: 'high', s: '## [HIGH] lodash@4.17.20 (npm)' },
    { t: 25.8, k: 'todo', s: 'What to do: Upgrade lodash to 4.18.1, the current release (fixes 4 of 4; the first fixed version 4.18.0 still has other known vulnerabilities).' },
    { t: 26.6, k: 'dim', s: '- GHSA-35jh-r3h4-6jhm (CVE-2021-23337) · severity HIGH · fixed in 4.17.21 · exploit probability 20%' },
    { t: 26.6, k: 'dim', s: '  Command Injection in lodash', wide: true },
    { t: 27.0, k: 'dim', s: '…' },
    { t: 28.2, k: 'gap' },
    { t: 28.2, k: 'plain', s: 'Sources:' },
    { t: 28.55, k: 'ok', s: '- OSV.dev (Google / OpenSSF): ok' },
    { t: 28.9, k: 'ok', s: '- CISA Known Exploited Vulnerabilities: ok' },
    { t: 29.25, k: 'ok', s: '- deps.dev (Google Open Source Insights): ok' },
    { t: 29.6, k: 'ok', s: '- CERT-FR (ANSSI, French government): ok' },
    { t: 29.95, k: 'ok', s: '- EPSS (FIRST.org): ok' },
  ],
  // Example package names for the planting scene (no version, no claim about them).
  packages: ['express', 'react', 'zod', 'vite', 'axios', 'eslint', 'dayjs', 'prettier'],
  risky: 'npm install lodash@4.17.20',
  fixed: 'lodash@4.18.1',
};
if (typeof module !== 'undefined') module.exports = COPY; else window.COPY = COPY;
