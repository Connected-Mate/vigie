"""The illustrated world of Vigie: a fire lookout over a forest at dawn.

Pure generator of inline SVG (no dependency). Every colour is a CSS class so the
same drawing serves light (dawn) and dark (before dawn) themes.
ViewBox 1600 x 560. The four "package trees" and the tower live in x 400..1160 so
that a phone crop keeps them all.
"""
from __future__ import annotations

import math
import random

W, H = 1600, 560
TOWER_X, TOWER_GROUND = 780, 318

# id, label, x, base y, height, width, state
PACKAGES = [
    ("leftpad", "left-pad", "1.3.0", 470, 506, 196, 112, "clear"),
    ("express", "express", "4.17.1", 660, 512, 222, 122, "wisp"),
    ("lodash", "lodash", "4.17.20", 900, 510, 238, 128, "smoke"),
    ("log4j", "log4j-core", "2.14.1", 1092, 504, 214, 120, "fire"),
]


def ridge_fn(base, comps, bump=None):
    def f(x):
        y = base + sum(a * math.sin(x / fq + ph) for a, fq, ph in comps)
        if bump:
            cx, hgt, wd = bump
            y -= hgt * math.exp(-(((x - cx) / wd) ** 2))
        return y
    return f


def ridge_path(f, x0=-40, x1=W + 40, step=24, drop=-2):
    pts = " ".join(f"{x},{f(x):.0f}" for x in range(x0, x1 + 1, step))
    return f"M{x0},{H + drop} L{pts} L{x1},{H + drop}Z"


def conifer(x, y, h, w):
    p = [(0, -h), (.30, -.60 * h), (.15, -.60 * h), (.41, -.31 * h), (.23, -.31 * h), (.5, -.05 * h), (.07, -.05 * h), (.07, 0)]
    pts = [(x + a * w, y + b) for a, b in p] + [(x - a * w, y + b) for a, b in reversed(p)]
    return "M" + " ".join(f"{px:.0f},{py:.0f}" for px, py in pts) + "Z"


def treeline(seed, f, hmin, hmax, smin, smax, x0=-30, x1=W + 30, skip=()):
    rnd = random.Random(seed)
    out, x = [], x0
    while x < x1:
        h = rnd.uniform(hmin, hmax)
        if not any(a <= x <= b for a, b in skip):
            out.append(conifer(x, f(x) + 3, h, h * rnd.uniform(.42, .56)))
        x += rnd.uniform(smin, smax)
    return "".join(out)


def big_tree(x, by, h, w):
    """A package tree: four soft tiers, a lit side and a shaded side."""
    full, shade = [], []
    for i in range(4):
        top = by - h + i * h * .19
        bottom = top + h * .37
        hw = w * (.20 + .10 * i)
        ht = bottom - top
        right = (f"M{x},{top:.1f} C{x + hw * .30:.1f},{top + ht * .52:.1f} {x + hw * .78:.1f},{bottom - ht * .14:.1f} {x + hw:.1f},{bottom:.1f} "
                 f"Q{x + hw * .5:.1f},{bottom - ht * .17:.1f} {x},{bottom - ht * .06:.1f}Z")
        left = (f"M{x},{top:.1f} C{x - hw * .30:.1f},{top + ht * .52:.1f} {x - hw * .78:.1f},{bottom - ht * .14:.1f} {x - hw:.1f},{bottom:.1f} "
                f"Q{x - hw * .5:.1f},{bottom - ht * .17:.1f} {x},{bottom - ht * .06:.1f}Z")
        full.append(left + right)
        shade.append(right)
    trunk = f'<rect class="c-trunk" x="{x - w * .05:.1f}" y="{by - h * .12:.1f}" width="{w * .10:.1f}" height="{h * .12 + 4:.1f}" rx="2"/>'
    return (trunk + f'<path class="c-tree tree-body" d="{"".join(full)}"/>'
            f'<path class="c-tree-shade tree-body" d="{"".join(shade)}"/>')


def flame(dx, dy, h, w, cls="flame", delay=0.0):
    d = f"M0,0 C{-w},{-h * .28:.1f} {-w * .45:.1f},{-h * .62:.1f} 0,{-h} C{w * .22:.1f},{-h * .66:.1f} {w},{-h * .34:.1f} 0,0Z"
    return f'<g transform="translate({dx:.1f},{dy:.1f})"><path class="{cls}" style="animation-delay:{delay}s" d="{d}"/></g>'


def puffs(x, top, n, spread, rmin, rmax, seed, cls):
    rnd = random.Random(seed)
    out = []
    for i in range(n):
        r = rnd.uniform(rmin, rmax)
        dx = rnd.uniform(-spread, spread)
        drift = rnd.uniform(18, 70)
        out.append(f'<circle class="puff {cls}" cx="{x + dx:.1f}" cy="{top + 6:.1f}" r="{r:.1f}" '
                   f'style="--d:{i * (4.6 / n):.2f}s;--dx:{drift:.0f}px;--k:{i / max(1, n - 1):.2f}"/>')
    return "".join(out)


def tower(cx=TOWER_X, gy=TOWER_GROUND):
    t = []
    a = t.append
    top = gy - 96
    # legs and bracing
    for sx in (-1, 1):
        a(f'<line x1="{cx + sx * 36}" y1="{gy + 6}" x2="{cx + sx * 21}" y2="{top}"/>')
        a(f'<line x1="{cx + sx * 12}" y1="{gy + 6}" x2="{cx + sx * 8}" y2="{top}"/>')
    levels = [gy + 2, gy - 30, gy - 62, top]
    halfw = lambda y: 36 - 15 * (gy + 6 - y) / (gy + 6 - top)
    for y in levels[:-1]:
        a(f'<line x1="{cx - halfw(y):.1f}" y1="{y}" x2="{cx + halfw(y):.1f}" y2="{y}"/>')
    for y0, y1 in zip(levels, levels[1:]):
        a(f'<line class="thin" x1="{cx - halfw(y0):.1f}" y1="{y0}" x2="{cx + halfw(y1):.1f}" y2="{y1}"/>')
        a(f'<line class="thin" x1="{cx + halfw(y0):.1f}" y1="{y0}" x2="{cx - halfw(y1):.1f}" y2="{y1}"/>')
    struct = f'<g class="c-tower-line">{"".join(t)}</g>'
    # deck, railing, cabin, roof
    deck = (f'<rect class="c-tower" x="{cx - 44}" y="{top - 3}" width="88" height="6" rx="1.5"/>'
            f'<g class="c-tower-line thin-all">'
            + "".join(f'<line x1="{cx + dx}" y1="{top - 3}" x2="{cx + dx}" y2="{top - 15}"/>' for dx in (-43, -34, 34, 43))
            + f'<line x1="{cx - 43}" y1="{top - 15}" x2="{cx - 29}" y2="{top - 15}"/><line x1="{cx + 29}" y1="{top - 15}" x2="{cx + 43}" y2="{top - 15}"/></g>')
    cab_top, cab_bot = top - 42, top - 3
    cabin = (f'<rect class="c-tower" x="{cx - 29}" y="{cab_top}" width="58" height="{cab_bot - cab_top}" rx="1.5"/>'
             f'<rect class="c-glass" x="{cx - 25}" y="{cab_top + 6}" width="50" height="17" rx="1"/>'
             + "".join(f'<line class="c-tower-line thin" x1="{cx + dx}" y1="{cab_top + 6}" x2="{cx + dx}" y2="{cab_top + 23}"/>' for dx in (-12.5, 0, 12.5))
             + f'<circle class="c-lamp" cx="{cx + 6}" cy="{cab_top + 14}" r="3.2"/>')
    roof = (f'<path class="c-roof" d="M{cx - 40},{cab_top + 1} L{cx},{cab_top - 22} L{cx + 40},{cab_top + 1}Z"/>'
            f'<line class="c-tower-line" x1="{cx}" y1="{cab_top - 22}" x2="{cx}" y2="{cab_top - 46}"/>'
            f'<path class="c-flag" d="M{cx},{cab_top - 46} l17,5 l-17,6Z"/>')
    stairs = f'<polyline class="c-tower-line thin" fill="none" points="{cx - 20},{gy + 4} {cx + 6},{gy - 30} {cx - 14},{gy - 62} {cx + 4},{top - 2}"/>'
    return f'<g class="tower">{struct}{stairs}{deck}{cabin}{roof}</g>'


def eye_xy():
    return TOWER_X + 6, TOWER_GROUND - 96 - 42 + 14


def scene_svg(alt: str) -> str:
    far1 = ridge_fn(236, [(26, 210, .4), (12, 77, 2.1), (5, 31, .9)])
    far2 = ridge_fn(274, [(22, 160, 2.6), (10, 58, .3), (4, 23, 1.7)])
    mid1 = ridge_fn(318, [(18, 190, 4.4), (9, 66, 1.2)])
    mid2 = ridge_fn(352, [(14, 230, 1.1), (7, 71, 3.3)], bump=(TOWER_X, 40, 120))
    near = ridge_fn(486, [(10, 260, .7), (5, 90, 2.2)])
    front = ridge_fn(532, [(8, 180, 3.9), (4, 60, .5)])

    rnd = random.Random(11)
    stars = "".join(
        f'<circle cx="{rnd.uniform(0, W):.0f}" cy="{rnd.uniform(0, 230):.0f}" r="{rnd.choice([.9, 1.1, 1.4, 1.8]):.1f}" style="--d:{rnd.uniform(0, 5):.1f}s"/>'
        for _ in range(70))

    pk = []
    for pid, _name, _ver, x, by, h, w, state in PACKAGES:
        top = by - h
        extra = ""
        if state == "clear":
            extra = (f'<g class="birds"><path d="M{x + 52},{top + 6} q7,-8 14,0 q7,-8 14,0"/>'
                     f'<path d="M{x + 86},{top - 16} q5,-6 10,0 q5,-6 10,0"/></g>')
        elif state == "wisp":
            extra = f'<g class="smoke smoke--wisp" filter="url(#soft)">{puffs(x, top + 8, 5, 3, 6, 10, 5, "puff--sm")}</g>'
        elif state == "smoke":
            extra = f'<g class="smoke smoke--col" filter="url(#soft)">{puffs(x, top + 20, 9, 9, 14, 27, 7, "puff--lg")}</g>'
        elif state == "fire":
            fl = "".join([
                flame(x - 30, by - 8, 58, 17, delay=.0), flame(x + 26, by - 6, 66, 19, delay=.35),
                flame(x - 6, by - 2, 84, 24, delay=.15), flame(x + 44, by - 2, 40, 13, delay=.5),
                flame(x - 46, by - 2, 34, 11, delay=.7),
                flame(x - 6, by - 2, 46, 13, cls="flame flame--in", delay=.2),
                flame(x + 26, by - 6, 34, 10, cls="flame flame--in", delay=.45),
                flame(x + 14, by - h * .46, 44, 14, delay=.6), flame(x - 18, by - h * .62, 30, 10, delay=.25),
            ])
            embers = "".join(
                f'<circle class="ember" cx="{x + dx}" cy="{by - 50}" r="{r}" style="--d:{d}s;--dx:{mx}px"/>'
                for dx, r, d, mx in ((-20, 2, 0, 26), (10, 1.6, .9, 40), (30, 2.2, 1.7, 18), (-4, 1.4, 2.4, 52), (20, 1.8, 3.1, 30)))
            extra = (f'<ellipse class="glow" cx="{x}" cy="{by - 30}" rx="150" ry="110" fill="url(#fireGlow)"/>'
                     f'<g class="smoke smoke--col smoke--dark" filter="url(#soft)">{puffs(x, top + 10, 8, 12, 15, 28, 3, "puff--lg")}</g>'
                     f'<g class="fire">{fl}{embers}</g>')
        pk.append(
            f'<g class="pkg pkg--{state}" data-pkg="{pid}" data-x="{x}" data-top="{top}">'
            f'<ellipse class="pkg__ring" cx="{x}" cy="{by + 2}" rx="{w * .62:.0f}" ry="11"/>'
            f'{big_tree(x, by, h, w)}{extra}</g>')

    ex, ey = eye_xy()
    skip_tower = ((TOWER_X - 46, TOWER_X + 46),)
    return f'''<svg class="scene__svg" viewBox="0 0 {W} {H}" preserveAspectRatio="xMidYMax meet" role="img" aria-label="{alt}">
<defs>
  <radialGradient id="sunHalo" cx="50%" cy="50%" r="50%"><stop offset="0" class="g-halo-0"/><stop offset="1" class="g-halo-1"/></radialGradient>
  <radialGradient id="fireGlow" cx="50%" cy="60%" r="50%"><stop offset="0" stop-color="#ff9a3d" stop-opacity=".55"/><stop offset="1" stop-color="#ff9a3d" stop-opacity="0"/></radialGradient>
  <linearGradient id="mist" x1="0" y1="0" x2="0" y2="1"><stop offset="0" class="g-mist-0"/><stop offset=".5" class="g-mist-1"/><stop offset="1" class="g-mist-0"/></linearGradient>
  <filter id="soft" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="5"/></filter>
</defs>
<g class="stars" aria-hidden="true">{stars}</g>
<g class="lay" data-depth=".04"><g class="lay__in" style="--i:0">
  <circle class="sun-halo" cx="585" cy="206" r="170" fill="url(#sunHalo)"/>
  <circle class="c-sun" cx="585" cy="206" r="40"/>
</g></g>
<g class="lay" data-depth=".08"><g class="lay__in" style="--i:1">
  <path class="c-r1" d="{ridge_path(far1)}"/>
</g></g>
<g class="lay" data-depth=".12"><g class="lay__in" style="--i:2">
  <path class="c-r2" d="{ridge_path(far2)}"/>
  <path class="c-r2" d="{treeline(21, far2, 9, 17, 7, 13)}"/>
</g></g>
<rect class="mist mist--a" x="-200" y="250" width="2000" height="70" fill="url(#mist)"/>
<g class="lay" data-depth=".17"><g class="lay__in" style="--i:3">
  <path class="c-r3" d="{ridge_path(mid1)}"/>
  <path class="c-r3" d="{treeline(22, mid1, 14, 27, 9, 16)}"/>
</g></g>
<rect class="mist mist--b" x="-200" y="300" width="2000" height="80" fill="url(#mist)"/>
<g class="lay" data-depth=".22"><g class="lay__in" style="--i:4">
  <path class="c-r4" d="{ridge_path(mid2)}"/>
  <path class="c-r4" d="{treeline(23, mid2, 20, 40, 11, 20, skip=skip_tower)}"/>
  {tower()}
</g></g>
<rect class="mist mist--c" x="-200" y="392" width="2000" height="90" fill="url(#mist)"/>
<g class="lay" data-depth=".3"><g class="lay__in" style="--i:5">
  <path class="c-ground" d="{ridge_path(near)}"/>
  <path class="c-ground" d="{treeline(24, near, 34, 62, 22, 44, skip=((400, 1160),))}"/>
  <line class="gaze" x1="{ex}" y1="{ey}" x2="{ex}" y2="{ey}"/>
  <circle class="reticle" cx="{ex}" cy="{ey}" r="15"/>
  {"".join(pk)}
</g></g>
<g class="lay" data-depth=".42"><g class="lay__in" style="--i:6">
  <path class="c-front" d="{ridge_path(front, drop=30)}"/>
  <path class="c-front" d="{treeline(25, front, 90, 170, 60, 120, x0=-20, x1=300)}{treeline(26, front, 90, 180, 60, 120, x0=1330, x1=W + 30)}"/>
  <path class="c-front" d="{treeline(27, front, 12, 26, 26, 60, x0=300, x1=1330)}"/>
</g></g>
</svg>'''


def strip_svg(seed: int, cls: str = "strip") -> str:
    """A thin treeline silhouette used as a section edge and in the footer."""
    f = ridge_fn(74, [(10, 170, seed), (5, 53, seed * 1.7)])
    pts = " ".join(f"{x},{f(x):.0f}" for x in range(-40, W + 41, 32))
    d = f"M-40,120 L{pts} L{W + 40},120Z"
    trees = treeline(seed, f, 16, 46, 16, 38)
    return (f'<svg class="{cls}" viewBox="0 0 {W} 120" preserveAspectRatio="none" aria-hidden="true" focusable="false">'
            f'<path d="{d}"/><path d="{trees}"/></svg>')


def icon_svg(size: int = 512) -> str:
    """App icon: the lookout cabin against the dawn, one thin smoke line on the horizon."""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="{size}" height="{size}">
<defs><linearGradient id="s" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#cfe0dc"/><stop offset=".62" stop-color="#f6e6cc"/><stop offset="1" stop-color="#f3bd8c"/></linearGradient>
<clipPath id="r"><rect width="512" height="512" rx="112"/></clipPath></defs>
<g clip-path="url(#r)">
<rect width="512" height="512" fill="url(#s)"/>
<circle cx="372" cy="318" r="58" fill="#fff3d6"/>
<path d="M352,300 c-16,-34 18,-52 4,-88 c-12,-30 14,-46 6,-74" fill="none" stroke="#6f7c77" stroke-width="13" stroke-linecap="round" opacity=".8"/>
<path d="M0,372 C90,330 170,352 256,372 S430,330 512,362 V512 H0Z" fill="#7fa594"/>
<path d="M0,420 C110,384 200,404 290,420 S450,392 512,410 V512 H0Z" fill="#2f5d4b"/>
<g fill="none" stroke="#1c2b25" stroke-width="13" stroke-linecap="round">
<path d="M150,440 L176,290 M266,440 L240,290 M158,392 L258,392 M166,340 L250,340"/>
<path d="M160,390 L248,342 M256,390 L168,342" stroke-width="7"/>
</g>
<rect x="128" y="276" width="160" height="16" rx="4" fill="#1c2b25"/>
<rect x="152" y="200" width="112" height="80" rx="5" fill="#1c2b25"/>
<rect x="164" y="214" width="88" height="34" rx="3" fill="#ffd98a"/>
<path d="M186,214 V248 M208,214 V248 M230,214 V248" stroke="#1c2b25" stroke-width="6"/>
<path d="M124,206 L208,154 L292,206Z" fill="#b4441c"/>
<path d="M0,470 C130,440 260,462 380,470 S480,452 512,460 V512 H0Z" fill="#1f3d32"/>
</g></svg>'''
