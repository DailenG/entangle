#!/usr/bin/env python3
"""Generates the Phase 1 logo concepts for the Entangle site, one per brand direction.

    python3 scripts/brand/directions.py

Writes into site/assets/logo/ (committed):
    <direction>-mark.svg      the symbol alone on a 48 x 32 grid
    <direction>-lockup.svg    symbol + "entangle" wordmark (Inter 600, from the site's own font)

Standard library only. Every shape is computed here so a chosen direction can be refined by
changing a constant and re-running, never by hand-editing paths. Colors are the direction's
palette tokens in site/styles.css; keep the two in step.
"""

import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "site/assets/logo"

# Palette tokens, mirrored from site/styles.css ([data-direction="…"]).
PALETTES = {
    "singlet": {"ink": "#1A1A1F", "a": "#C8431F", "b": "#176B6B"},
    "spacelike": {"ink": "#ECEBE6", "a": "#F0B23A", "b": "#F0B23A"},
    "swap": {"ink": "#EFEBE0", "a": "#D7935B", "b": "#D7935B"},
    "bound": {"ink": "#0F1B1E", "a": "#0F7A5A", "b": "#9AA7AC"},
}


def f(v):
    return ("%.2f" % v).rstrip("0").rstrip(".")


def half_disc(cx, cy, r, angle_deg, side, fill):
    """One half of a disc, cut by a diameter at angle_deg; side = +1 or -1 picks the half."""
    a = math.radians(angle_deg)
    dx, dy = math.cos(a) * r, math.sin(a) * r
    x1, y1 = cx + dx, cy + dy
    x2, y2 = cx - dx, cy - dy
    sweep = 1 if side > 0 else 0
    return '<path d="M%s %s A%s %s 0 0 %d %s %s Z" fill="%s"/>' % (
        f(x1), f(y1), f(r), f(r), sweep, f(x2), f(y2), fill)


def singlet(p):
    """Two particles in a spin singlet: measured along the same axis they are always opposite.
    Each disc is cut by the same measurement axis; the filled halves are on opposite sides."""
    r, ang = 10, -32
    out = []
    for cx, side, col in ((13, +1, p["a"]), (35, -1, p["b"])):
        out.append('<circle cx="%d" cy="16" r="%d" fill="none" stroke="%s" stroke-width="1.5"/>' % (cx, r, p["ink"]))
        out.append(half_disc(cx, 16, r - 0.75, ang, side, col))
    return "\n".join(out)


def spacelike(p):
    """Two events outside each other's light cone. The cone is the X of a spacetime diagram
    (time up); the two dots sit on one time slice, where no signal can have passed between them."""
    out = ['<path d="M14 3 L34 29 M34 3 L14 29" fill="none" stroke="%s" stroke-width="1.5" stroke-linecap="round"/>' % p["ink"]]
    for cx in (5, 43):
        out.append('<circle cx="%d" cy="16" r="3.25" fill="%s"/>' % (cx, p["a"]))
    return "\n".join(out)


def swap(p):
    """Entanglement swapping: two short-range pairs (A-R, R-C) become one long-range pair (A-C)
    after a measurement at R, which is left holding nothing. The repeater in one glyph."""
    y = 22
    out = []
    out.append('<path d="M6 %d Q15 8 24 %d Q33 8 42 %d" fill="none" stroke="%s" stroke-width="1.5" stroke-linecap="round" opacity=".45"/>' % (y, y, y, p["ink"]))
    out.append('<path d="M6 %d Q24 -10 42 %d" fill="none" stroke="%s" stroke-width="2" stroke-linecap="round"/>' % (y, y, p["a"]))
    out.append('<circle cx="6" cy="%d" r="3.5" fill="%s"/>' % (y, p["a"]))
    out.append('<circle cx="42" cy="%d" r="3.5" fill="%s"/>' % (y, p["a"]))
    out.append('<circle cx="24" cy="%d" r="3" fill="none" stroke="%s" stroke-width="1.5"/>' % (y, p["ink"]))
    return "\n".join(out)


def bound(p):
    """Bell's theorem as a plot: the quantum correlation (a cosine) rising above the straight
    line that is the most any local hidden-variable model can reach."""
    out = []
    out.append('<path d="M5 27 L24 9 L43 27" fill="none" stroke="%s" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>' % p["b"])
    # -cos sampled; a smooth cosine from 5 to 43 peaking at 24.
    pts = []
    for i in range(0, 41):
        t = i / 40
        x = 5 + 38 * t
        y = 27 - 23 * (0.5 - 0.5 * math.cos(2 * math.pi * t))
        pts.append("%s%s %s" % ("M" if i == 0 else "L", f(x), f(y)))
    out.append('<path d="%s" fill="none" stroke="%s" stroke-width="2.25" stroke-linecap="round"/>' % (" ".join(pts), p["a"]))
    return "\n".join(out)


MARKS = {"singlet": singlet, "spacelike": spacelike, "swap": swap, "bound": bound}


def svg(w, h, body, extra=""):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d"%s>\n%s\n</svg>\n'
            % (w, h, w, h, extra, body))


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, fn in MARKS.items():
        p = PALETTES[name]
        mark = fn(p)
        (OUT / ("%s-mark.svg" % name)).write_text(svg(48, 32, mark, ' role="img" aria-label="Entangle"'))
        word = ('<text x="58" y="23.5" font-family="Inter, ui-sans-serif, system-ui, sans-serif" font-size="22" '
                'font-weight="600" letter-spacing="-0.44" fill="%s">entangle</text>' % p["ink"])
        (OUT / ("%s-lockup.svg" % name)).write_text(svg(152, 32, mark + "\n" + word, ' role="img" aria-label="Entangle"'))
        print("wrote", name)


if __name__ == "__main__":
    main()
