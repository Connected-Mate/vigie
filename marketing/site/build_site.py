#!/usr/bin/env python3
"""Build the Vigie showcase site (FR + EN) into docs/.

    python3 marketing/site/build_site.py            # from the repo root

Order of work (house skill `new-project-site`):
  1. `scaffold.py project.json .` was run once: it wrote the plumbing in docs/
     (sitemap, robots, manifest, icons, .nojekyll) and marketing/ADS-KIT.md.
  2. This script keeps the scaffold's <head> (canonical, hreflang, OG, JSON-LD)
     and replaces the body with Vigie's own world: the lookout scene, the live
     demo fed with REAL tool output (marketing/site/real/*.txt), and every section.
Sources: project.json (facts, texts in `site_copy`, SEO in `seo`), this folder
(style.css, site.js, scene.py, fonts/, real/). docs/video/ belongs to the video lead:
if docs/video/vigie-<lang>.mp4 exists it is used (with .webm, .vtt, poster-<lang>.jpg, transcript-<lang>.txt), otherwise the film is shown as "being made".
Nothing here publishes anything.
"""
from __future__ import annotations

import html
import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
DOCS = ROOT / "docs"
SKILL = Path.home() / ".claude/skills/new-project-site/scripts/scaffold.py"

sys.path.insert(0, str(HERE))
import scene  # noqa: E402

spec = importlib.util.spec_from_file_location("scaffold", SKILL)
scaffold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scaffold)

SHEET = json.loads((ROOT / "project.json").read_text(encoding="utf-8"))
C = SHEET["site_copy"]
REPO = SHEET["source_repo"]
REAL = {p.stem.replace("real-", ""): p.read_text(encoding="utf-8").rstrip("\n") for p in (HERE / "real").glob("*.txt")}

# Small interface words that are not marketing copy.
UI = {
    "fr": {"skip": "Aller au contenu", "home": "accueil", "lang_nav": "Langue", "other": "English version", "other_short": "EN",
           "nav": "Sections", "n_watch": "Sources", "n_report": "Rapports", "n_limits": "Limites", "n_faq": "Questions",
           "works": "Fonctionne avec", "slip": "Rapport de la vigie", "asked": "L'agent demande", "trees": "Les quatre arbres surveillés",
           "more": "+ {n} autres failles pour cette brique dans le rapport complet", "full": "Voir le rapport complet",
           "real": "Vraie sortie de Vigie", "tabs": "Exemples de réponses", "t_blocked": "Installation bloquée", "t_clean": "Rien à signaler",
           "t_incomplete": "Contrôle incomplet", "t_unreachable": "Bases injoignables", "t_full": "Rapport complet",
           "c_full": "Le rapport complet du tour de guet ci-dessus : quatre briques vérifiées d'un coup, classées par urgence.",
           "sources": "Sources", "useful": "Liens utiles", "issues": "Signaler un souci", "code": "Code source", "legal": "Mentions légales",
           "x": "sur X", "quick": "Navigation rapide", "setup": "Installer", "features": "Fonctions", "faq": "Questions",
           "state": {"clear": "sain", "wisp": "filet de fumée", "smoke": "fumée", "fire": "incendie"},
           "prio": {"clear": "rien de connu", "wisp": "priorité moyenne", "smoke": "priorité haute", "fire": "à traiter tout de suite"},
           "video_soon": "Bientôt ici", "credits": "Polices Besley et Hanken Grotesk (licence OFL). Logos des agents : Simple Icons (CC0) ; ces marques appartiennent à leurs propriétaires et sont citées pour dire avec quoi Vigie fonctionne, sans partenariat.",
           "privacy": "Ce site ne dépose aucun cookie et ne te suit pas.", "manual_cmd": "La commande, pour Claude Code",
           "og_locale": "fr_FR"},
    "en": {"skip": "Skip to content", "home": "home", "lang_nav": "Language", "other": "Version française", "other_short": "FR",
           "nav": "Sections", "n_watch": "Sources", "n_report": "Reports", "n_limits": "Limits", "n_faq": "Questions",
           "works": "Works with", "slip": "Lookout report", "asked": "The agent asks", "trees": "The four trees being watched",
           "more": "+ {n} more for this package in the full report", "full": "See the full report",
           "real": "Real Vigie output", "tabs": "Sample answers", "t_blocked": "Install blocked", "t_clean": "All clear",
           "t_incomplete": "Incomplete check", "t_unreachable": "Databases unreachable", "t_full": "Full report",
           "c_full": "The full report from the watch above: four packages checked in one call, sorted by urgency.",
           "sources": "Sources", "useful": "Useful links", "issues": "Report a problem", "code": "Source code", "legal": "Legal notice",
           "x": "on X", "quick": "Quick navigation", "setup": "Set up", "features": "Features", "faq": "Questions",
           "state": {"clear": "healthy", "wisp": "a wisp of smoke", "smoke": "smoke", "fire": "fire"},
           "prio": {"clear": "nothing known", "wisp": "medium priority", "smoke": "high priority", "fire": "act now"},
           "video_soon": "Coming here soon", "credits": "Typefaces Besley and Hanken Grotesk (OFL licence). Agent logos: Simple Icons (CC0); these brands belong to their owners and are named to say what Vigie works with, with no partnership implied.",
           "privacy": "This site sets no cookie and does not track you.", "manual_cmd": "The command, for Claude Code",
           "og_locale": "en_US"},
}
LEGAL = scaffold.LEGAL_URL
esc = lambda s: html.escape(s or "", quote=True)


def tx(node, lang):
    return esc(node[lang])


# ————————————————————————————————————————————— real report → HTML (colour only, text untouched)

def report_html(text: str) -> str:
    out = []
    for line in text.split("\n"):
        e = esc(line)
        cls = ""
        if line.startswith("VERDICT") or line.startswith("Vigie blocked") or line.startswith("Vigie could not"):
            cls = "l-verdict"
        elif line.startswith("## ["):
            tag = re.match(r"## \[([A-Z ]+)\]", line).group(1)
            e = e.replace(f"[{tag}]", f'<b class="tag tag--{tag.lower().replace(" ", "")}">{tag}</b>', 1)
            cls = "l-head"
        elif line.startswith("What to do:"):
            cls = "l-do"
        elif line.strip().startswith("https://"):
            cls = "l-url"
        elif line.startswith("Sources:") or line.startswith("Limits:") or line.startswith("Not checked"):
            cls = "l-meta"
        out.append(f'<span class="l {cls}">{e}\n</span>' if e else '<span class="l l-gap">\n</span>')
    return "".join(out)


def split_report(text: str):
    """→ verdict line, {package name: section text} from the real 4-package report."""
    head, *rest = text.split("\n## ")
    sections = {}
    for block in rest:
        block = block.split("\n\nSources:")[0]
        name = re.match(r"\[[A-Z ]+\] (\S+?)@", block).group(1)
        sections[name] = "## " + block.rstrip()
    return head.strip(), sections


def excerpt(section: str, keep: int = 2):
    lines = section.split("\n")
    head, vulns = lines[:2], lines[2:]
    groups, cur = [], []
    for ln in vulns:
        if ln.startswith("- ") and cur:
            groups.append(cur)
            cur = []
        cur.append(ln)
    if cur:
        groups.append(cur)
    shown = [l for g in groups[:keep] for l in g]
    return "\n".join(head + shown), max(0, len(groups) - keep)


VERDICT, SECTIONS = split_report(REAL["full-report"])
PKG_SECTION = {"express": "express", "lodash": "lodash", "log4j": "org.apache.logging.log4j:log4j-core"}


# ————————————————————————————————————————————— pieces

def agent_chips(lang, small=False):
    keys = SHEET["agent_setup"].get("agents") or scaffold.DEFAULT_AGENTS
    if small:
        items = "".join(f'<li title="{esc(scaffold.AGENTS[k][0])}">{scaffold.agent_icon(scaffold.AGENTS[k][1], scaffold.AGENTS[k][0])}'
                        f'<span class="sr-only">{esc(scaffold.AGENTS[k][0])}</span></li>' for k in keys)
        return f'<ul class="with" role="list">{items}</ul>'
    items = "".join(f'<li class="agent" style="--i:{i}">{scaffold.agent_icon(scaffold.AGENTS[k][1], scaffold.AGENTS[k][0])}<span>{esc(scaffold.AGENTS[k][0])}</span></li>'
                    for i, k in enumerate(keys))
    return f'<ul class="agents" role="list">{items}<li class="agent agent--any" style="--i:{len(keys)}"><span>{tx(C["agent"]["any"], lang)}</span></li></ul>'


def copy_button(lang, label_node, copied_node, cls="btn btn--go btn--lg"):
    icon = ('<svg class="btn__ic" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            '<rect x="9" y="9" width="11" height="11" rx="2.5"/><path d="M5 15V6.5A2.5 2.5 0 0 1 7.500 4H15"/></svg>'
            '<svg class="btn__ok" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12.5l4.500 4.500L19 7.500"/></svg>')
    return (f'<button class="{cls}" type="button" data-copy="{tx(C["agent"]["prompt"], lang)}" data-copied="{tx(copied_node, lang)}">'
            f'{icon}<span data-copy-label>{tx(label_node, lang)}</span></button>')


def hero(lang, prefix):
    ui = UI[lang]
    h = C["hero"]
    tabs, panels = [], []
    for i, (pid, name, ver, x, by, _h, _w, state) in enumerate(scene.PACKAGES):
        sel = "true" if pid == "log4j" else "false"
        tabs.append(
            f'<button class="tree tree--{state}" role="tab" id="tab-{pid}" aria-controls="panel-{pid}" aria-selected="{sel}" '
            f'tabindex="{0 if pid == "log4j" else -1}" data-pkg="{pid}" style="--n:{i};--x:{x / scene.W * 100:.2f}%;--y:{(by + 12) / scene.H * 100:.2f}%">'
            f'<span class="tree__dot" aria-hidden="true"></span><span class="tree__name">{esc(name)}<span class="tree__ver">{esc(ver)}</span></span>'
            f'<span class="sr-only">, {ui["state"][state]}</span></button>')
        if pid == "leftpad":
            body = REAL["clean"].split("\n\nSources:")[0]
            more = ""
            call = "check_packages · left-pad@1.3.0"
        else:
            body, n = excerpt(SECTIONS[PKG_SECTION[pid]])
            more = f'<p class="slip__more">{ui["more"].format(n=n)}</p>' if n else ""
            call = ""
        panels.append(
            f'<div class="slip__panel" role="tabpanel" id="panel-{pid}" aria-labelledby="tab-{pid}" data-pkg="{pid}"{"" if pid == "log4j" else " hidden"}>'
            f'<p class="slip__say"><span class="pill pill--{state}">{ui["prio"][state]}</span>{tx(h["trees"][pid], lang)}</p>'
            + (f'<p class="slip__call">{esc(call)}</p>' if call else "")
            + f'<pre class="term" lang="en" tabindex="0" aria-label="{ui["real"]}">{report_html(body)}</pre>{more}</div>')
    alt = tx(C["hero_alt"], lang)
    return f'''<section class="hero" aria-labelledby="title" data-demo>
  <div class="hero__sky" aria-hidden="true"></div>
  <div class="wrap hero__grid">
    <div class="hero__text">
      <p class="badge">{tx(C["badge"], lang)}</p>
      <h1 class="display" id="title">{tx(C["headline"], lang)}</h1>
      <p class="lede">{tx(C["lede"], lang)}</p>
      <div class="cta">
        {copy_button(lang, h["cta"], h["cta_copied"])}
        <a class="btn btn--ghost btn--lg" href="#watch">{tx(h["secondary"], lang)}</a>
      </div>
      <div class="hero__with"><span>{ui["works"]}</span>{agent_chips(lang, small=True)}</div>
      <p class="fine">{tx(C["platform"], lang)}</p>
    </div>
    <div class="slip" id="demo" aria-label="{ui["slip"]}" role="group">
      <div class="slip__head">
        <span class="slip__title">{tx(h["demo_title"], lang)}</span>
        <span class="slip__asked">{ui["asked"]} <code>check_packages</code></span>
      </div>
      <pre class="term term--verdict" lang="en" aria-label="{ui["real"]}">{report_html(VERDICT)}</pre>
      {"".join(panels)}
      <p class="slip__foot"><a href="#report">{ui["full"]}</a></p>
    </div>
  </div>
  <div class="scene-wrap">
    <div class="scene">
      {scene.scene_svg(alt)}
      <div class="trees" role="tablist" aria-label="{ui["trees"]}">{"".join(tabs)}</div>
    </div>
  </div>
  <div class="wrap hero__under">
    <p class="hero__hint"><span class="js-only">{tx(h["tree_hint"], lang)} </span>{tx(h["demo_note"], lang)}</p>
    <ul class="legend" role="list">
      <li><span class="tree__dot dot--clear" aria-hidden="true"></span>{tx(h["legend"]["clear"], lang)}</li>
      <li><span class="tree__dot dot--smoke" aria-hidden="true"></span>{tx(h["legend"]["smoke"], lang)}</li>
      <li><span class="tree__dot dot--fire" aria-hidden="true"></span>{tx(h["legend"]["fire"], lang)}</li>
    </ul>
    <button class="btn btn--quiet js-only" type="button" data-replay>
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 12a8 8 0 1 0 2.600-5.900"/><path d="M4 4.500V9h4.500"/></svg>
      {tx(h["replay"], lang)}</button>
  </div>
</section>'''


SIGNS = {
    0: '<path d="M14 40c-5-9 6-13 1-22s5-12 2-16"/><path d="M26 40c-3-7 5-10 2-17"/>',
    1: '<path d="M20 4c2 8 11 11 11 21a11 11 0 0 1-22 0c0-5 3-8 5-11 1 4 3 5 4 5 0-6 0-10 2-15z"/>',
    2: '<path d="M8 4v36"/><path d="M8 8l24 4-4 5 4 5-24 4"/>',
    3: '<rect x="7" y="5" width="26" height="32" rx="3"/><path d="M13 14h14M13 21h14M13 28h8"/>',
}


def sections(lang, prefix):
    ui = UI[lang]
    out = []
    a = C["agent"]
    steps = "".join(f'<li style="--i:{i}">{tx(s, lang)}</li>' for i, s in enumerate(a["steps"]))
    out.append(f'''<section class="wrap section agent-setup" id="agent" aria-labelledby="agent-title" data-reveal>
  <div class="agent-setup__text">
    <h2 class="h2" id="agent-title">{tx(a["title"], lang)}</h2>
    <p class="section__lede">{tx(a["text"], lang)}</p>
    <div class="prompt">{copy_button(lang, a["copy"], a["copied"])}</div>
  </div>
  <div class="agent-setup__crew">
    {agent_chips(lang)}
    <ol class="agent-steps">{steps}</ol>
  </div>
</section>''')

    w = C["watch"]
    items = "".join(
        f'<li class="post" style="--i:{i}"><svg class="post__ic" viewBox="0 0 40 44" width="40" height="44" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{SIGNS[i]}</svg>'
        f'<p class="post__sign">{tx(it["sign"], lang)}</p><h3>{esc(it["name"])}</h3><p>{tx(it["text"], lang)}</p></li>'
        for i, it in enumerate(w["items"]))
    out.append(f'''<section class="wrap section" id="watch" aria-labelledby="watch-title" data-reveal>
  <h2 class="h2" id="watch-title">{tx(w["title"], lang)}</h2>
  <p class="section__lede">{tx(w["lede"], lang)}</p>
  <ul class="posts" role="list">{items}</ul>
</section>''')

    feats = "".join(f'<li class="feature" style="--i:{i}"><span class="feature__n" aria-hidden="true">{i + 1:02d}</span><h3>{tx(f["title"], lang)}</h3><p>{tx(f["text"], lang)}</p></li>'
                    for i, f in enumerate(C["features"]))
    out.append(f'''<section class="wrap section" id="features" aria-labelledby="features-title" data-reveal>
  <h2 class="h2" id="features-title">{tx(C["features_title"], lang)}</h2>
  <p class="section__lede">{tx(C["features_lede"], lang)}</p>
  <ol class="features" role="list">{feats}</ol>
</section>''')

    r = C["report"]
    tabs_def = [("blocked", REAL["hook-blocked"], r["captions"]["blocked"][lang]), ("clean", REAL["clean"], r["captions"]["clean"][lang]),
                ("incomplete", REAL["incomplete"], r["captions"]["incomplete"][lang]), ("unreachable", REAL["hook-unreachable"], r["captions"]["unreachable"][lang]),
                ("full", REAL["full-report"], ui["c_full"])]
    tabs = "".join(f'<button role="tab" id="rt-{k}" aria-controls="rp-{k}" aria-selected="{"true" if i == 0 else "false"}" tabindex="{0 if i == 0 else -1}">{ui["t_" + k]}</button>'
                   for i, (k, _t, _c) in enumerate(tabs_def))
    pans = "".join(
        f'<figure class="out" role="tabpanel" id="rp-{k}" aria-labelledby="rt-{k}"{"" if i == 0 else " data-tabhide"}>'
        f'<figcaption><span class="out__k">{ui["t_" + k]}</span>{esc(cap)}</figcaption>'
        f'<pre class="term term--big" lang="en" tabindex="0" aria-label="{ui["real"]} : {ui["t_" + k]}">{report_html(text)}</pre></figure>'
        for i, (k, text, cap) in enumerate(tabs_def))
    out.append(f'''<section class="section section--night" id="report" aria-labelledby="report-title">
  {scene.strip_svg(3, "strip strip--top")}
  <div class="wrap" data-reveal>
    <h2 class="h2" id="report-title">{tx(r["title"], lang)}</h2>
    <p class="section__lede">{tx(r["lede"], lang)}</p>
    <div class="outs" data-tabs>
      <div class="outs__tabs" role="tablist" aria-label="{ui["tabs"]}">{tabs}</div>
      <div class="outs__panels">{pans}</div>
    </div>
  </div>
</section>''')

    ins = C["install"]
    isteps = "".join(f'<li style="--i:{i}"><h3>{tx(s["title"], lang)}</h3><p>{tx(s["text"], lang)}</p></li>' for i, s in enumerate(ins["steps"]))
    out.append(f'''<section class="wrap section" id="install" aria-labelledby="install-title" data-reveal>
  <h2 class="h2" id="install-title">{tx(ins["title"], lang)}</h2>
  <p class="section__lede">{tx(ins["lede"], lang)}</p>
  <ol class="steps">{isteps}</ol>
  <p class="steps__more"><a class="link" href="{REPO}#install" rel="noopener">{tx(ins["manual"], lang)}</a></p>
</section>''')

    lim = C["limits"]
    litems = "".join(f'<li style="--i:{i}"><h3>{tx(s["title"], lang)}</h3><p>{tx(s["text"], lang)}</p></li>' for i, s in enumerate(lim["items"]))
    out.append(f'''<section class="section section--fog" id="limits" aria-labelledby="limits-title">
  <div class="wrap" data-reveal>
    <h2 class="h2" id="limits-title">{tx(lim["title"], lang)}</h2>
    <p class="section__lede">{tx(lim["lede"], lang)}</p>
    <ul class="limits" role="list">{litems}</ul>
  </div>
</section>''')

    out.append(video_section(lang, prefix))

    out.append(f'''<section class="wrap section duo" data-reveal>
  <div class="duo__a" id="source" aria-labelledby="source-title">
    <h2 class="h2" id="source-title">{tx(C["source"]["title"], lang)}</h2>
    <p>{tx(C["source"]["text"], lang)}</p>
    <a class="btn btn--ghost btn--lg" href="{REPO}" rel="noopener">{tx(C["source"]["btn"], lang)}</a>
  </div>
  <div class="duo__b" id="coffee" aria-labelledby="coffee-title">
    <svg class="mug" viewBox="0 0 64 64" width="64" height="64" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      <path class="mug__steam" d="M24 6c-3 4 3 6 0 10"/><path class="mug__steam" d="M34 4c-3 4 3 6 0 10"/>
      <path d="M12 24h36v18a12 12 0 0 1-12 12H24a12 12 0 0 1-12-12V24z"/><path d="M48 29h4a7 7 0 0 1 0 14h-4"/></svg>
    <h2 class="h2" id="coffee-title">{tx(C["coffee"]["title"], lang)}</h2>
    <p>{tx(C["coffee"]["text"], lang)}</p>
    <a class="btn btn--paper btn--lg" href="{esc(SHEET["coffee"]["url"])}" rel="noopener" data-coffee>{tx(C["coffee"]["btn"], lang)}</a>
  </div>
</section>''')

    qas = "".join(f'<details class="qa"><summary>{tx(q["q"], lang)}</summary><div class="qa__a"><p>{tx(q["a"], lang)}</p></div></details>' for q in C["faq"])
    out.append(f'''<section class="wrap section section--faq" id="faq" aria-labelledby="faq-title" data-reveal>
  <h2 class="h2" id="faq-title">{scaffold.UI[lang]["faq_long"]}</h2>
  <div class="faq">{qas}</div>
</section>''')
    return "\n".join(out)


def video_section(lang, prefix):
    """Uses the video lead's files when docs/video/manifest.json exists; otherwise says the film is being made."""
    v = C["video"]
    ui = UI[lang]
    vd = DOCS / "video"
    mp4 = vd / f"vigie-{lang}.mp4"
    if mp4.exists() and mp4.stat().st_size > 200_000:
        names = {"webm": f"vigie-{lang}.webm", "mp4": f"vigie-{lang}.mp4"}
        srcs = "".join(f'<source src="{prefix}video/{n}" type="video/{k}">' for k, n in names.items() if (vd / n).exists())
        track = (f'<track kind="captions" src="{prefix}video/vigie-{lang}.vtt" srclang="{lang}" label="{"Français" if lang == "fr" else "English"}" default>'
                 if (vd / f"vigie-{lang}.vtt").exists() else "")
        tfile = vd / f"transcript-{lang}.txt"
        lines = [x.strip() for x in tfile.read_text(encoding="utf-8").splitlines() if x.strip()] if tfile.exists() else []
        intro, items = [], []
        for x in lines:
            if re.match(r"\d+:\d\d", x):
                t_, _, rest = x.partition(" ")
                items.append([t_, rest.strip(), ""])
            elif items:
                items[-1][2] += (" " if items[-1][2] else "") + x
            else:
                intro.append(x)
        lis = "".join(f'<li><span class="tc">{esc(a)}</span> {esc(b)} <span class="td">{esc(c)}</span></li>' for a, b, c in items)
        tr = (f'<details class="video__text" id="video-text"><summary>{tx(v["transcript_label"], lang)}</summary>'
              f'{"".join(f"<p>{esc(x)}</p>" for x in intro)}<ul role="list">{lis}</ul></details>' if lines else "")
        poster = f' poster="{prefix}video/poster-{lang}.jpg"' if (vd / f"poster-{lang}.jpg").exists() else ""
        inner = (f'<div class="video__frame"><video muted loop playsinline controls preload="none"{poster}'
                 f'{" aria-describedby=" + chr(34) + "video-text" + chr(34) if tr else ""}>{srcs}{track}</video></div>{tr}')
    else:
        inner = (f'<div class="video__frame video__frame--soon"><div class="video__soon">{scene.strip_svg(9, "strip strip--video")}'
                 f'<p><strong>{ui["video_soon"]}</strong>{tx(v["pending"], lang)}</p></div></div>')
    return f'''<section class="wrap section" id="video" aria-labelledby="video-title" data-reveal>
  <h2 class="h2" id="video-title">{tx(v["title"], lang)}</h2>
  {inner}
</section>'''


def faq_ld(lang):
    ld = {"@context": "https://schema.org", "@type": "FAQPage", "inLanguage": lang,
          "mainEntity": [{"@type": "Question", "name": q["q"][lang], "acceptedAnswer": {"@type": "Answer", "text": q["a"][lang]}} for q in C["faq"]]}
    return json.dumps(ld, ensure_ascii=False, indent=1).replace("</", "<\\/")


def page(lang):
    ui = UI[lang]
    default = SHEET["default_lang"]
    other = "en" if lang == "fr" else "fr"
    prefix = "" if lang == default else "../"
    other_href = f"{other}/" if lang == default else "../"
    key = f"{SHEET['slug']}-lang"
    head = scaffold.render_page(SHEET, lang).split("</head>")[0]
    # richer SoftwareApplication (real facts only), fonts, theme colour, FAQ data
    extra = SHEET.get("seo", {}).get("software_extra", {})
    if extra:
        feats = json.dumps(extra.get("featureList", {}).get(lang, []), ensure_ascii=False)
        add = f',\n  "softwareVersion": "{extra["softwareVersion"]}",\n  "softwareRequirements": "{extra["softwareRequirements"]}",\n  "featureList": {feats}\n}}'
        i = head.rindex("}\n</script>")
        head = head[:i].rstrip() + add + head[i + 1:]
    head = head.replace('<link rel="stylesheet"',
                        f'<link rel="preload" href="{prefix}assets/fonts/besley.woff2" as="font" type="font/woff2" crossorigin>\n'
                        f'<link rel="preload" href="{prefix}assets/fonts/hanken.woff2" as="font" type="font/woff2" crossorigin>\n'
                        f'<link rel="icon" href="{prefix}assets/icon.svg" type="image/svg+xml">\n'
                        '<meta name="theme-color" content="#dbe7e4" media="(prefers-color-scheme: light)">\n'
                        '<meta name="theme-color" content="#0b1420" media="(prefers-color-scheme: dark)">\n'
                        '<link rel="stylesheet"', 1)
    head = re.sub(r"<style>@media \(prefers-color-scheme: light\).*?</style>\n?", "", head, flags=re.S)
    head += f'<script type="application/ld+json">\n{faq_ld(lang)}\n</script>\n</head>'

    mark = f'<img src="{prefix}assets/icon-192.png" alt="" width="32" height="32">'
    header = f'''<a class="skip" href="#content">{ui["skip"]}</a>
<header class="top">
  <div class="wrap top__in">
    <a class="mark" href="./" aria-label="{esc(SHEET["name"])}, {ui["home"]}">{mark}<span>{esc(SHEET["name"])}</span></a>
    <nav class="top__nav" aria-label="{ui["nav"]}">
      <a href="#watch">{ui["n_watch"]}</a><a href="#report">{ui["n_report"]}</a><a href="#limits">{ui["n_limits"]}</a><a href="#faq">{ui["n_faq"]}</a>
    </nav>
    <nav class="langs" aria-label="{ui["lang_nav"]}">
      <span aria-current="true">{lang.upper()}</span>
      <a href="{other_href}" data-lang="{other}" data-lang-key="{key}" hreflang="{other}" lang="{other}" aria-label="{ui["other"]}">{ui["other_short"]}</a>
    </nav>
  </div>
</header>'''
    handle = SHEET["links"]["x"].rstrip("/").rsplit("/", 1)[-1]
    links = "".join([
        f'<a href="{REPO}/issues" rel="noopener">{ui["issues"]}</a>',
        f'<a href="{REPO}" rel="noopener">{ui["code"]}</a>',
        f'<a href="{esc(SHEET["coffee"]["url"])}" rel="noopener">{tx(C["coffee"]["btn"], lang)}</a>',
        f'<a href="{esc(SHEET["links"]["x"])}" rel="noopener">@{esc(handle)} {ui["x"]}</a>',
        f'<a href="{LEGAL[lang]}">{ui["legal"]}</a>',
        f'<a href="{other_href}" data-lang="{other}" data-lang-key="{key}" hreflang="{other}" lang="{other}">{ui["other"]}</a>',
    ])
    import datetime
    footer = f'''<footer class="foot">
  {scene.strip_svg(5, "strip strip--foot")}
  <div class="foot__in">
    <div class="wrap foot__grid">
      <div>
        <a class="mark" href="./">{mark.replace(">", ' loading="lazy">', 1)}<span>{esc(SHEET["name"])}</span></a>
        <p class="foot__note">{tx(C["footer_note"], lang)}</p>
      </div>
      <nav aria-label="{ui["useful"]}">{links}</nav>
      <p class="foot__fine">© {datetime.date.today().year} Connected Mate. {ui["privacy"]} {ui["credits"]}</p>
    </div>
  </div>
</footer>
<nav class="capsule" aria-label="{ui["quick"]}">
  <a href="#features">{ui["features"]}</a>
  <a href="#faq">{ui["faq"]}</a>
  <a class="btn btn--go" href="#agent">{ui["setup"]}</a>
</nav>'''
    return f'''{head}
<body>
{header}
<main id="content">
{hero(lang, prefix)}
{sections(lang, prefix)}
</main>
{footer}
<script src="{prefix}site.js" defer></script>
</body>
</html>
'''


def page_404():
    d = SHEET["default_lang"]
    o = "en" if d == "fr" else "fr"
    root = scaffold.base_url(SHEET)
    n = C["notfound"]
    return f'''<!DOCTYPE html>
<html lang="{d}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(n["title"][d])} — {esc(SHEET["name"])}</title>
<meta name="robots" content="noindex">
<meta name="color-scheme" content="light dark">
<link rel="icon" href="{root}assets/favicon-32.png" sizes="32x32" type="image/png">
<link rel="stylesheet" href="{root}style.css">
</head>
<body class="nf">
<main class="wrap notfound">
  <h1 class="display">{esc(n["title"][d])}</h1>
  <p class="lede">{esc(n["text"][d])}</p>
  <p><a class="btn btn--go btn--lg" href="{root}">{esc(n["back"][d])}</a></p>
  <p lang="{o}" class="fine">{esc(n["text"][o])} <a class="link" href="{root}{o}/">{esc(n["back"][o])}</a></p>
</main>
{scene.strip_svg(5, "strip strip--foot")}
</body>
</html>
'''


def og_page(lang):
    """Source page of the 1200x630 social image (rendered to JPG by render_assets.mjs)."""
    return f'''<!DOCTYPE html><html lang="{lang}"><head><meta charset="utf-8"><link rel="stylesheet" href="../../../docs/style.css">
<style>html,body{{margin:0;width:1200px;height:630px;overflow:hidden}}</style></head>
<body class="ogp"><div class="og"><div class="hero__sky"></div>
<div class="og__scene">{scene.scene_svg("")}</div>
<div class="og__text"><p class="og__brand"><img src="../../../docs/assets/icon-192.png" alt="" width="54" height="54">Vigie</p>
<p class="og__h">{tx(C["og"]["line1"], lang)}<br>{tx(C["og"]["line2"], lang)}</p>
<p class="og__s">{tx(C["badge"], lang)}</p></div></div></body></html>'''


def main():
    DOCS.mkdir(exist_ok=True)
    other = "en" if SHEET["default_lang"] == "fr" else "fr"
    (DOCS / other).mkdir(exist_ok=True)
    (DOCS / "assets" / "fonts").mkdir(parents=True, exist_ok=True)
    for f in ("style.css", "site.js"):
        shutil.copyfile(HERE / f, DOCS / f)
    for f in (HERE / "fonts").glob("*"):
        shutil.copyfile(f, DOCS / "assets" / "fonts" / f.name)
    (DOCS / "assets" / "icon.svg").write_text(scene.icon_svg(), encoding="utf-8")
    (DOCS / "index.html").write_text(page(SHEET["default_lang"]), encoding="utf-8")
    (DOCS / other / "index.html").write_text(page(other), encoding="utf-8")
    (DOCS / "404.html").write_text(page_404(), encoding="utf-8")
    llms = SHEET.get("seo", {}).get("llms_txt")
    if llms:
        (DOCS / "llms.txt").write_text(llms.rstrip() + "\n", encoding="utf-8")
    build = HERE / "_build"
    build.mkdir(exist_ok=True)
    for lang in ("fr", "en"):
        (build / f"og-{lang}.html").write_text(og_page(lang), encoding="utf-8")
    print(f"built {DOCS}")


if __name__ == "__main__":
    main()
