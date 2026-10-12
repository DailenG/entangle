/* Entangle website, Phase 1: four switchable brand directions.
   Switching changes html[data-direction] (palette), the header mark, the hero copy and the hero
   animation. Picker: fixed card on desktop; pill under the hero visual, or a tap on the visual,
   opens a sheet on narrow screens. Speed: normal or quarter. Reduced motion: a still frame.
   Query: ?d=<id>&speed=quarter, plus ?t=<seconds>&picker=open for previews. Plain script, no dependencies. */
(function () {
  "use strict";

  var DIRECTIONS = [
    {
      id: "singlet",
      name: "Singlet",
      desc: "Paper and ink. Two spins measured on the same axis: always opposite.",
      eyebrow: "Local-first MCP · Agent to agent",
      title: "Two agents, one state.",
      lead: "Entangle lets AI agents on your network find each other, pair under a human's eye, and share files and JSON over end-to-end encrypted links. Nothing in between can read them.",
      mark: markSinglet,
      anim: AnimSinglet
    },
    {
      id: "spacelike",
      name: "Spacelike",
      desc: "Dark bench, amber trace. Two events no signal could connect.",
      eyebrow: "Encrypted agent-to-agent sync",
      title: "Same state. Any distance.",
      lead: "Agents on your LAN discover each other over mDNS; agents on different networks meet through a repeater you host. Either way the link is Noise-encrypted end to end.",
      mark: markSpacelike,
      anim: AnimSpacelike
    },
    {
      id: "swap",
      name: "Swap",
      desc: "Chalkboard and copper. Entanglement swapping, the repeater's trick.",
      eyebrow: "MCP server for agent collaboration",
      title: "Entangle your agents.",
      lead: "Discovery on the LAN, a three-emoji check by a human, then files and JSON flow between agents over an encrypted link, direct or through a blind Quantum Repeater you run yourself.",
      mark: markSwap,
      anim: AnimSwap
    },
    {
      id: "bound",
      name: "Bound",
      desc: "Lab notebook. Bell's inequality, violated live, one pair at a time.",
      eyebrow: "Agent-to-agent, measured",
      title: "Share state, not secrets.",
      lead: "An open-source Rust MCP server: agents find each other over mDNS, a human approves each pairing with a three-emoji check, and every sync is Noise-encrypted and SHA-256 verified.",
      mark: markBound,
      anim: AnimBound
    }
  ];

  var root = document.documentElement;
  var canvas = document.getElementById("hero-canvas");
  var caption = document.getElementById("hero-caption");
  var figure = canvas && canvas.parentNode;
  var markSlot = document.querySelector(".brand-mark");
  var copyEls = { eyebrow: q("eyebrow"), title: q("title"), lead: q("lead") };
  function q(k) { return document.querySelector('[data-copy="' + k + '"]'); }

  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  var params = new URLSearchParams(location.search);
  var store = safeStorage();
  var speed = (params.get("speed") || store.get("entangle.speed") || "normal") === "quarter" ? 0.25 : 1;
  var current = null, anim = null, raf = 0, last = 0, simTime = 0, visible = true, inView = true;

  // ---------- marks (header); same geometry as scripts/brand/directions.py ----------
  function halfDisc(cx, cy, r, deg, side, fill) {
    var a = deg * Math.PI / 180, dx = Math.cos(a) * r, dy = Math.sin(a) * r;
    return '<path d="M' + (cx + dx) + ' ' + (cy + dy) + ' A' + r + ' ' + r + ' 0 0 ' + (side > 0 ? 1 : 0) + ' ' + (cx - dx) + ' ' + (cy - dy) + ' Z" fill="' + fill + '"/>';
  }
  function markSinglet(c) {
    return '<circle cx="13" cy="16" r="10" fill="none" stroke="' + c.ink + '" stroke-width="1.5"/>' + halfDisc(13, 16, 9.25, -32, 1, c.a) +
      '<circle cx="35" cy="16" r="10" fill="none" stroke="' + c.ink + '" stroke-width="1.5"/>' + halfDisc(35, 16, 9.25, -32, -1, c.b);
  }
  function markSpacelike(c) {
    return '<path d="M14 3 L34 29 M34 3 L14 29" fill="none" stroke="' + c.ink + '" stroke-width="1.5" stroke-linecap="round"/>' +
      '<circle cx="5" cy="16" r="3.25" fill="' + c.a + '"/><circle cx="43" cy="16" r="3.25" fill="' + c.a + '"/>';
  }
  function markSwap(c) {
    return '<path d="M6 22 Q15 8 24 22 Q33 8 42 22" fill="none" stroke="' + c.ink + '" stroke-width="1.5" stroke-linecap="round" opacity=".45"/>' +
      '<path d="M6 22 Q24 -10 42 22" fill="none" stroke="' + c.a + '" stroke-width="2" stroke-linecap="round"/>' +
      '<circle cx="6" cy="22" r="3.5" fill="' + c.a + '"/><circle cx="42" cy="22" r="3.5" fill="' + c.a + '"/>' +
      '<circle cx="24" cy="22" r="3" fill="none" stroke="' + c.ink + '" stroke-width="1.5"/>';
  }
  function markBound(c) {
    var d = "";
    for (var i = 0; i <= 40; i++) { var t = i / 40; d += (i ? "L" : "M") + (5 + 38 * t).toFixed(2) + " " + (27 - 23 * (0.5 - 0.5 * Math.cos(2 * Math.PI * t))).toFixed(2) + " "; }
    return '<path d="M5 27 L24 9 L43 27" fill="none" stroke="' + c.b + '" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>' +
      '<path d="' + d + '" fill="none" stroke="' + c.a + '" stroke-width="2.25" stroke-linecap="round"/>';
  }

  // ---------- helpers ----------
  function safeStorage() {
    try { var s = window.localStorage; s.setItem("entangle.t", "1"); s.removeItem("entangle.t"); return { get: function (k) { return s.getItem(k); }, set: function (k, v) { s.setItem(k, v); } }; }
    catch (e) { var m = {}; return { get: function (k) { return m[k] || null; }, set: function (k, v) { m[k] = v; } }; }
  }
  function tokens() {
    var cs = getComputedStyle(root);
    function v(n) { return cs.getPropertyValue(n).trim(); }
    return { bg: v("--bg"), surface: v("--surface"), sunken: v("--sunken"), line: v("--line"), lineStrong: v("--line-strong"), ink: v("--ink"), body: v("--body"), muted: v("--muted"), a: v("--a"), b: v("--b") };
  }
  function hash(k) { var x = Math.sin(k * 12.9898 + 78.233) * 43758.5453; return x - Math.floor(x); }
  function ease(t) { t = Math.min(1, Math.max(0, t)); return 1 - Math.pow(1 - t, 3); }
  function clamp01(t) { return Math.min(1, Math.max(0, t)); }
  function lerp(a, b, t) { return a + (b - a) * t; }
  function withAlpha(hex, a) {
    var h = hex.replace("#", ""); if (h.length === 3) h = h.replace(/./g, function (ch) { return ch + ch; });
    var n = parseInt(h, 16); return "rgba(" + (n >> 16 & 255) + "," + (n >> 8 & 255) + "," + (n & 255) + "," + a + ")";
  }
  function mono(px) { return (px || 12) + 'px ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace'; }
  function sans(px, w) { return (w || 500) + " " + px + 'px Inter, ui-sans-serif, system-ui, sans-serif'; }
  function pad(n, w) { var s = String(n); while (s.length < w) s = "0" + s; return s; }

  // ---------- 1. Singlet: repeated spin measurements on a Bell pair ----------
  function AnimSinglet(ctx, c) {
    this.T = 3.2;
    this.draw = function (w, h, t, still) {
      var k = Math.floor(t / this.T), u = (t - k * this.T) / this.T;
      var angPrev = hash(k - 1) * 180 - 90, ang = hash(k) * 180 - 90;
      var s = hash(k + 0.5) > 0.5 ? 1 : -1;
      if (still) { u = 0.6; }
      var rot = lerp(angPrev, ang, ease(u / 0.16));
      var fill = u < 0.16 ? 0 : u < 0.22 ? ease((u - 0.16) / 0.06) : u < 0.9 ? 1 : 1 - ease((u - 0.9) / 0.1);
      var R = Math.min(w, h) * 0.2, cy = h * 0.44, ax = w * 0.3, bx = w * 0.7;
      ctx.clearRect(0, 0, w, h);
      // common measurement axis, drawn as a hairline across both
      ctx.save(); ctx.strokeStyle = c.lineStrong; ctx.lineWidth = 1; ctx.setLineDash([3, 5]);
      var a = rot * Math.PI / 180, L = Math.min(w, h) * 0.46;
      [ax, bx].forEach(function (cx) {
        ctx.beginPath(); ctx.moveTo(cx - Math.cos(a) * L / 2, cy - Math.sin(a) * L / 2); ctx.lineTo(cx + Math.cos(a) * L / 2, cy + Math.sin(a) * L / 2); ctx.stroke();
      });
      ctx.restore();
      [[ax, 1, c.a], [bx, -1, c.b]].forEach(function (d) {
        var cx = d[0], side = d[1] * s, col = d[2];
        ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.lineWidth = 1.5; ctx.strokeStyle = c.ink; ctx.stroke();
        if (fill > 0) {
          ctx.save(); ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.clip();
          ctx.translate(cx, cy); ctx.rotate(a);
          ctx.globalAlpha = fill; ctx.fillStyle = col;
          ctx.fillRect(-R - 1, side > 0 ? -R - 1 : 0, 2 * R + 2, R + 1);
          ctx.restore();
        }
      });
      ctx.fillStyle = c.muted; ctx.font = sans(12, 600); ctx.textAlign = "center"; ctx.textBaseline = "alphabetic";
      ctx.fillText("A", ax, cy + R + 24); ctx.fillText("B", bx, cy + R + 24);
      ctx.font = mono(11.5); ctx.fillText("axis " + pad(Math.round(rot + 90), 3) + "\u00b0", w / 2, cy - R - 10);
      // ledger of recent outcomes
      var n = Math.min(k + 1, 12), y0 = h * 0.87, gap = Math.min(36, (w - 48) / 12);
      var x0 = w / 2 - (n - 1) * gap / 2;
      ctx.font = mono(15); ctx.textAlign = "center";
      for (var i = 0; i < n; i++) {
        var kk = k - n + 1 + i, so = hash(kk + 0.5) > 0.5 ? 1 : -1, alpha = kk === k ? fill : 1;
        if (kk < 0) continue;
        ctx.globalAlpha = alpha; ctx.fillStyle = c.a; ctx.fillText(so > 0 ? "\u2191" : "\u2193", x0 + i * gap - 6, y0);
        ctx.fillStyle = c.b; ctx.fillText(so > 0 ? "\u2193" : "\u2191", x0 + i * gap + 6, y0);
      }
      ctx.globalAlpha = 1;
      return "trial " + pad(k + 1, 4) + " \u00b7 axis " + pad(Math.round(ang + 90), 3) + "\u00b0 \u00b7 A " + (s > 0 ? "\u2191" : "\u2193") + "  B " + (s > 0 ? "\u2193" : "\u2191") + " \u00b7 agreements 0 / " + (k + 1);
    };
  }

  // ---------- 2. Spacelike: a Minkowski diagram; two simultaneous outcomes, light cones still on their way ----------
  function AnimSpacelike(ctx, c) {
    this.P = 8;
    this.draw = function (w, h, t, still) {
      var narrow = w < 700;
      var X = narrow ? w * 0.44 : Math.min(w * 0.39, 560), xc = w / 2;
      var base = h * 0.8, spd = X / 5.5;            // light crosses the midpoint 5.5 s after the pair fires
      if (still) t = 4.5;
      ctx.clearRect(0, 0, w, h);
      // grid: equal spacing in x and t so light moves at 45 degrees
      var unit = X / 4;
      ctx.strokeStyle = c.line; ctx.lineWidth = 1; ctx.beginPath();
      for (var y = base; y > -1; y -= unit) { ctx.moveTo(0, y); ctx.lineTo(w, y); }
      for (var y2 = base + unit; y2 < h; y2 += unit) { ctx.moveTo(0, y2); ctx.lineTo(w, y2); }
      for (var x = xc % unit; x < w; x += unit) { ctx.moveTo(x, 0); ctx.lineTo(x, h); }
      ctx.stroke();
      // worldlines of the two machines
      ctx.strokeStyle = c.lineStrong; ctx.lineWidth = 1.5; ctx.beginPath();
      ctx.moveTo(xc - X, 0); ctx.lineTo(xc - X, h); ctx.moveTo(xc + X, 0); ctx.lineTo(xc + X, h); ctx.stroke();
      ctx.fillStyle = c.muted; ctx.font = mono(12); ctx.textAlign = "center"; ctx.textBaseline = "alphabetic";
      ctx.fillText("A", xc - X, 22); ctx.fillText("B", xc + X, 22);
      if (!narrow) { ctx.textAlign = "right"; ctx.fillText("x \u2192", w - 20, h - 18); ctx.fillText("t \u2191", w - 20, h - 36); }
      var kNow = Math.floor(t / this.P), out = "";
      for (var k = kNow; k >= kNow - 1; k--) {
        if (k < 0) continue;
        var age = t - k * this.P, reach = age * spd;
        var alpha = k === kNow ? Math.min(1, age / 0.4) : Math.max(0, 1 - age / this.P - 0) * 0;
        if (k !== kNow) { alpha = Math.max(0, 1 - (age - this.P) / 1.2); }
        if (alpha <= 0) continue;
        var s = hash(k + 0.5) > 0.5 ? 1 : -1;
        ctx.save(); ctx.globalAlpha = alpha;
        // light cones opening upward from each event
        ctx.strokeStyle = withAlpha(c.a, 0.6); ctx.lineWidth = 1; ctx.beginPath();
        ctx.moveTo(xc - X, base); ctx.lineTo(xc - X + reach, base - reach); ctx.moveTo(xc - X, base); ctx.lineTo(xc - X - reach, base - reach);
        ctx.moveTo(xc + X, base); ctx.lineTo(xc + X - reach, base - reach); ctx.moveTo(xc + X, base); ctx.lineTo(xc + X + reach, base - reach);
        ctx.stroke();
        // the same instant in this frame: a dotted line between the two events
        ctx.setLineDash([2, 6]); ctx.strokeStyle = c.lineStrong; ctx.beginPath(); ctx.moveTo(xc - X + 10, base); ctx.lineTo(xc + X - 10, base); ctx.stroke(); ctx.setLineDash([]);
        // outcomes, always opposite
        ctx.fillStyle = c.a;
        [[xc - X, s], [xc + X, -s]].forEach(function (e) {
          ctx.beginPath(); ctx.arc(e[0], base, 4.5, 0, Math.PI * 2); ctx.fill();
          ctx.font = mono(14); ctx.textAlign = "center"; ctx.fillText(e[1] > 0 ? "\u2191" : "\u2193", e[0] + (e[0] < xc ? -18 : 18), base + 5);
        });
        // milestones: the two cones meet halfway; later, light from A arrives at B's worldline
        if (reach >= X) { ctx.beginPath(); ctx.arc(xc, base - X, 3, 0, Math.PI * 2); ctx.fillStyle = c.a; ctx.fill(); }
        if (reach >= 2 * X && base - 2 * X > 30) { ctx.beginPath(); ctx.arc(xc + X, base - 2 * X, 3.5, 0, Math.PI * 2); ctx.fillStyle = c.ink; ctx.fill(); }
        ctx.restore();
        if (k === kNow) {
          var pct = Math.min(100, Math.round(100 * reach / (2 * X)));
          out = "pair " + pad(k + 1, 4) + " \u00b7 A " + (s > 0 ? "\u2191" : "\u2193") + "  B " + (s > 0 ? "\u2193" : "\u2191") + " \u00b7 light from A is " + pct + "% of the way to B";
        }
      }
      return out;
    };
  }

  // ---------- 3. Swap: entanglement swapping, the repeater's one trick ----------
  function AnimSwap(ctx, c) {
    this.T = 9;
    function arc(ctx, x1, x2, y, lift, from, to) {
      // quadratic arc sampled so it can be drawn partially
      var cx = (x1 + x2) / 2, cy = y - lift, n = 48; ctx.beginPath();
      for (var i = 0; i <= n; i++) {
        var u = from + (to - from) * i / n, mt = 1 - u;
        var x = mt * mt * x1 + 2 * mt * u * cx + u * u * x2, yy = mt * mt * y + 2 * mt * u * cy + u * u * y;
        if (i === 0) ctx.moveTo(x, yy); else ctx.lineTo(x, yy);
      }
      ctx.stroke();
    }
    this.draw = function (w, h, t, still) {
      var k = Math.floor(t / this.T), u = t - k * this.T;
      if (still) u = 6;
      var y = h * 0.6, ax = w * 0.12, rx = w / 2, cx = w * 0.88, r = Math.max(5, Math.min(w * 0.014, 9));
      var liftS = h * 0.42, liftL = h * 0.9;
      var short = u < 1.6 ? ease(u / 1.6) : 1, shortA = u < 4.2 ? 1 : u < 5.2 ? 1 - ease((u - 4.2) / 1) : 0;
      var measure = u >= 3 && u < 4.2 ? (u - 3) / 1.2 : -1;
      var longDraw = u < 4.2 ? 0 : u < 5.4 ? ease((u - 4.2) / 1.2) : 1;
      var fadeAll = u > 8.2 ? 1 - (u - 8.2) / 0.8 : 1;
      ctx.clearRect(0, 0, w, h);
      ctx.globalAlpha = fadeAll;
      ctx.lineCap = "round";
      // baseline, chalk
      ctx.strokeStyle = c.line; ctx.lineWidth = 1; ctx.setLineDash([1, 7]); ctx.beginPath(); ctx.moveTo(ax, y); ctx.lineTo(cx, y); ctx.stroke(); ctx.setLineDash([]);
      // the two short pairs
      if (shortA > 0 && short > 0) {
        ctx.globalAlpha = fadeAll * shortA * 0.7; ctx.strokeStyle = c.ink; ctx.lineWidth = 1.5;
        arc(ctx, ax, rx, y, liftS, 0, short); arc(ctx, cx, rx, y, liftS, 0, short);
        ctx.globalAlpha = fadeAll;
      }
      // classical bits from the repeater to both ends
      if (measure >= 0) {
        var p = ease(measure), bx1 = lerp(rx, ax, p), bx2 = lerp(rx, cx, p);
        ctx.fillStyle = c.ink; ctx.beginPath(); ctx.arc(bx1, y, 3, 0, 7); ctx.fill(); ctx.beginPath(); ctx.arc(bx2, y, 3, 0, 7); ctx.fill();
      }
      // the long pair
      if (longDraw > 0) { ctx.strokeStyle = c.a; ctx.lineWidth = 2.25; arc(ctx, ax, cx, y, liftL, 0.5 - longDraw / 2, 0.5 + longDraw / 2); }
      // nodes
      ctx.fillStyle = c.a; ctx.beginPath(); ctx.arc(ax, y, r, 0, 7); ctx.fill(); ctx.beginPath(); ctx.arc(cx, y, r, 0, 7); ctx.fill();
      var rr = measure >= 0 ? r * (1 - 0.35 * Math.sin(measure * Math.PI)) : r;
      ctx.strokeStyle = c.ink; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.arc(rx, y, rr, 0, 7); ctx.stroke();
      if (u < 3) { ctx.fillStyle = withAlpha(c.ink, 0.35); ctx.beginPath(); ctx.arc(rx, y, rr * 0.55, 0, 7); ctx.fill(); }
      // labels
      ctx.fillStyle = c.muted; ctx.font = mono(12); ctx.textAlign = "center";
      ctx.fillText("A", ax, y + r + 22); ctx.fillText("repeater", rx, y + r + 22); ctx.fillText("C", cx, y + r + 22);
      ctx.font = sans(13, 500);
      var label = u < 3 ? "A\u2013R and R\u2013C are each entangled" : u < 4.2 ? "Bell-state measurement at R; two classical bits go to A and C" : u < 8.2 ? "A and C are now entangled; R holds nothing" : "";
      ctx.fillStyle = c.body; ctx.fillText(label, rx, h - 10);
      ctx.globalAlpha = 1;
      return "cycle " + pad(k + 1, 3) + " \u00b7 A\u2013R, R\u2013C \u2192 A\u2013C \u00b7 the repeater keeps two bits, never the state";
    };
  }

  // ---------- 4. Bound: Bell's inequality violated live ----------
  function AnimBound(ctx, c) {
    var BINS = 36, RATE = 42, N_MAX = 1400, HOLD = 4;
    this.draw = function (w, h, t, still) {
      var cycle = N_MAX / RATE + HOLD, k = Math.floor(t / cycle), u = t - k * cycle;
      if (still) u = N_MAX / RATE;
      var n = Math.min(N_MAX, Math.floor(u * RATE));
      var fade = u > cycle - 0.6 ? (cycle - u) / 0.6 : 1;
      var same = new Array(BINS).fill(0), tot = new Array(BINS).fill(0);
      for (var i = 0; i < n; i++) {
        var bin = Math.floor(hash(k * 7919 + i) * BINS), th = (bin + 0.5) / BINS * Math.PI;
        tot[bin]++; if (hash(k * 7919 + i + 0.5) < Math.pow(Math.sin(th / 2), 2)) same[bin]++;
      }
      var narrow = w < 700, mL = narrow ? 44 : 56, mR = 24, mT = 36, mB = narrow ? 48 : 56;
      var px = function (deg) { return mL + (w - mL - mR) * deg / 180; }, py = function (E) { return mT + (h - mT - mB) * (1 - E) / 2; };
      ctx.clearRect(0, 0, w, h);
      ctx.globalAlpha = fade;
      // axes and ticks
      ctx.strokeStyle = c.line; ctx.lineWidth = 1; ctx.beginPath();
      [-1, -0.5, 0, 0.5, 1].forEach(function (E) { ctx.moveTo(mL, py(E)); ctx.lineTo(w - mR, py(E)); }); ctx.stroke();
      ctx.strokeStyle = c.lineStrong; ctx.beginPath(); ctx.moveTo(mL, py(0)); ctx.lineTo(w - mR, py(0)); ctx.moveTo(mL, mT); ctx.lineTo(mL, h - mB); ctx.stroke();
      ctx.fillStyle = c.muted; ctx.font = mono(11.5); ctx.textAlign = "center"; ctx.textBaseline = "alphabetic";
      [0, 45, 90, 135, 180].forEach(function (d) { ctx.fillText(d + "\u00b0", px(d), h - mB + 18); });
      ctx.textAlign = "right"; [-1, 0, 1].forEach(function (E) { ctx.fillText((E > 0 ? "+" : "") + E, mL - 8, py(E) + 4); });
      ctx.textAlign = "left"; ctx.fillText("E(\u03b8)", mL - 32, mT - 14); ctx.textAlign = "right"; ctx.fillText("\u03b8 between analyzers", w - mR, h - mB + 36);
      // the local-realist limit: perfect anticorrelation at 0 forces a straight line
      ctx.setLineDash([5, 5]); ctx.strokeStyle = c.b; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.moveTo(px(0), py(-1)); ctx.lineTo(px(180), py(1)); ctx.stroke(); ctx.setLineDash([]);
      // quantum prediction
      ctx.strokeStyle = withAlpha(c.a, 0.35); ctx.lineWidth = 1.5; ctx.beginPath();
      for (var d = 0; d <= 180; d += 2) { var yq = py(-Math.cos(d * Math.PI / 180)); if (d === 0) ctx.moveTo(px(d), yq); else ctx.lineTo(px(d), yq); }
      ctx.stroke();
      // measured points with error bars
      for (var b = 0; b < BINS; b++) {
        if (!tot[b]) continue;
        var E = (2 * same[b] - tot[b]) / tot[b], se = Math.min(1, 1 / Math.sqrt(tot[b])), xd = (b + 0.5) / BINS * 180;
        ctx.strokeStyle = c.a; ctx.lineWidth = 1.25; ctx.beginPath(); ctx.moveTo(px(xd), py(Math.max(-1, E - se))); ctx.lineTo(px(xd), py(Math.min(1, E + se))); ctx.stroke();
        ctx.fillStyle = c.a; ctx.beginPath(); ctx.arc(px(xd), py(E), 2.75, 0, 7); ctx.fill();
      }
      // the latest pair, as a tick at +1 or -1
      if (n > 0 && n < N_MAX) {
        var lb = Math.floor(hash(k * 7919 + n - 1) * BINS), lth = (lb + 0.5) / BINS * Math.PI, ls = hash(k * 7919 + n - 1 + 0.5) < Math.pow(Math.sin(lth / 2), 2) ? 1 : -1;
        ctx.strokeStyle = c.ink; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(px((lb + 0.5) / BINS * 180), py(ls) - 5); ctx.lineTo(px((lb + 0.5) / BINS * 180), py(ls) + 5); ctx.stroke();
      }
      // legend
      ctx.font = sans(narrow ? 11.5 : 12.5, 500); ctx.textAlign = "left";
      var lx = px(8), ly = py(0.88);
      var lw = Math.max(ctx.measureText("any local hidden-variable model").width, ctx.measureText("measured \u00b7 quantum: \u2212cos \u03b8").width) + 30;
      ctx.fillStyle = c.surface; ctx.globalAlpha = fade * 0.92; ctx.fillRect(lx - 8, ly - 12, lw + 16, 46); ctx.globalAlpha = fade;
      ctx.strokeStyle = c.a; ctx.lineWidth = 2; ctx.beginPath(); ctx.moveTo(lx, ly); ctx.lineTo(lx + 22, ly); ctx.stroke();
      ctx.fillStyle = c.body; ctx.fillText("measured \u00b7 quantum: \u2212cos \u03b8", lx + 30, ly + 4);
      ctx.setLineDash([5, 5]); ctx.strokeStyle = c.b; ctx.lineWidth = 1.5; ctx.beginPath(); ctx.moveTo(lx, ly + 22); ctx.lineTo(lx + 22, ly + 22); ctx.stroke(); ctx.setLineDash([]);
      ctx.fillText("any local hidden-variable model", lx + 30, ly + 26);
      ctx.globalAlpha = 1;
      var viol = 0; [8, 9, 26, 27].forEach(function (b) { if (tot[b] > 25) { var E = (2 * same[b] - tot[b]) / tot[b], lim = -1 + 2 * (b + 0.5) / BINS; if (Math.abs(E - lim) > 1 / Math.sqrt(tot[b]) && Math.abs(E) > Math.abs(lim)) viol++; } });
      return "n = " + n.toLocaleString("en-US") + " pairs \u00b7 " + BINS + " settings \u00b7 bound exceeded at " + viol + " of 4 checked angles";
    };
  }

  // ---------- engine ----------
  var ctx = canvas.getContext("2d");
  function size() {
    var r = canvas.getBoundingClientRect(), dpr = Math.min(2, window.devicePixelRatio || 1);
    var W = Math.max(1, Math.round(r.width * dpr)), H = Math.max(1, Math.round(r.height * dpr));
    if (canvas.width !== W || canvas.height !== H) { canvas.width = W; canvas.height = H; }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { w: r.width, h: r.height };
  }
  function frame(now) {
    raf = 0;
    if (!anim) return;
    var dt = last ? Math.min(0.1, (now - last) / 1000) : 0; last = now;
    simTime += dt * speed;
    var s = size();
    var text = anim.draw(s.w, s.h, simTime, false);
    if (text !== undefined && caption.textContent !== text) caption.textContent = text;
    if (!reduced.matches && visible && inView) raf = requestAnimationFrame(frame);
  }
  function drawStill() {
    var s = size(); var text = anim.draw(s.w, s.h, 0, true); if (text !== undefined) caption.textContent = text;
  }
  function start() {
    if (raf) cancelAnimationFrame(raf); raf = 0; last = 0;
    if (reduced.matches) { drawStill(); return; }
    if (visible && inView) raf = requestAnimationFrame(frame);
  }
  function apply(id, push) {
    var d = DIRECTIONS.filter(function (x) { return x.id === id; })[0] || DIRECTIONS[0];
    current = d;
    root.setAttribute("data-direction", d.id);
    var c = tokens();
    markSlot.innerHTML = d.mark(c);
    copyEls.eyebrow.textContent = d.eyebrow; copyEls.title.textContent = d.title; copyEls.lead.textContent = d.lead;
    anim = new d.anim(ctx, c);
    simTime = parseFloat(params.get("t")) || 0;
    store.set("entangle.direction", d.id);
    document.querySelectorAll(".dir-toggle strong, .dir-pill strong").forEach(function (el) { el.textContent = d.name; });
    var radio = document.getElementById("dir-" + d.id); if (radio) radio.checked = true;
    if (push) { var p = new URLSearchParams(location.search); p.set("d", d.id); if (speed !== 1) p.set("speed", "quarter"); else p.delete("speed"); history.replaceState(null, "", location.pathname + "?" + p.toString() + location.hash); }
    start();
  }
  function setSpeed(v, push) {
    speed = v; store.set("entangle.speed", v === 1 ? "normal" : "quarter");
    if (push) { var p = new URLSearchParams(location.search); if (v !== 1) p.set("speed", "quarter"); else p.delete("speed"); var qs = p.toString(); history.replaceState(null, "", location.pathname + (qs ? "?" + qs : "") + location.hash); }
  }

  // ---------- picker ----------
  function buildPicker() {
    var picker = document.createElement("aside");
    picker.className = "dir-picker"; picker.id = "dir-picker"; picker.setAttribute("aria-label", "Brand direction picker");
    var html = '<div class="dir-picker-head"><h2>Direction</h2><button type="button" class="dir-picker-close" aria-label="Close"><svg class="icon" aria-hidden="true"><use href="#i-x"/></svg></button></div>' +
      '<p class="dir-picker-sub">Phase 1 preview. Switches palette, mark, copy and hero.</p><div class="dir-options" role="radiogroup" aria-label="Direction">';
    DIRECTIONS.forEach(function (d, i) {
      html += '<input type="radio" name="direction" id="dir-' + d.id + '" value="' + d.id + '">' +
        '<label for="dir-' + d.id + '"><span class="dir-num">' + (i + 1) + '</span><span class="dir-name">' + d.name + '</span><span class="dir-desc">' + d.desc + '</span></label>';
    });
    html += '</div><div class="dir-speed" role="radiogroup" aria-label="Animation speed"><span class="dir-speed-label">Speed</span>' +
      '<input type="radio" name="speed" id="speed-normal" value="1"><label for="speed-normal">Normal</label>' +
      '<input type="radio" name="speed" id="speed-quarter" value="0.25"><label for="speed-quarter">\u00bc speed</label></div>' +
      '<p class="dir-picker-note">Keys 1\u20134 switch direction, Q toggles speed. Reduced-motion users get a still frame.</p>';
    picker.innerHTML = html;
    var backdrop = document.createElement("div"); backdrop.className = "dir-backdrop";
    var corner = document.createElement("div"); corner.className = "dir-corner";
    var pill = document.createElement("button");
    pill.type = "button"; pill.className = "dir-pill"; pill.setAttribute("aria-controls", "dir-picker"); pill.setAttribute("aria-expanded", "false");
    pill.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#i-sliders"/></svg><span>Direction: <strong></strong></span><kbd>1\u20134</kbd>';
    corner.appendChild(picker); corner.appendChild(pill);
    document.body.appendChild(backdrop); document.body.appendChild(corner);

    var toggle = document.createElement("button");
    toggle.type = "button"; toggle.className = "dir-toggle"; toggle.setAttribute("aria-controls", "dir-picker"); toggle.setAttribute("aria-expanded", "false");
    toggle.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#i-sliders"/></svg><span>Direction: <strong></strong></span>';
    figure.parentNode.insertBefore(toggle, figure.nextSibling);

    function open() { picker.classList.add("is-open"); backdrop.classList.add("is-open"); toggle.setAttribute("aria-expanded", "true"); pill.setAttribute("aria-expanded", "true"); var r = picker.querySelector("input:checked"); if (r) r.focus(); }
    function close() { picker.classList.remove("is-open"); backdrop.classList.remove("is-open"); toggle.setAttribute("aria-expanded", "false"); pill.setAttribute("aria-expanded", "false"); }
    function isSheet() { return window.matchMedia("(max-width: 900px)").matches; }
    function flip() { picker.classList.contains("is-open") ? close() : open(); }
    toggle.addEventListener("click", flip); pill.addEventListener("click", flip);
    if (params.get("picker") === "open") open();
    backdrop.addEventListener("click", close);
    picker.querySelector(".dir-picker-close").addEventListener("click", close);
    var sheetMq = window.matchMedia("(max-width: 900px)");
    function syncFigureRole() {
      if (sheetMq.matches) { figure.setAttribute("role", "button"); figure.setAttribute("tabindex", "0"); figure.setAttribute("aria-label", "Open the direction picker"); }
      else { figure.removeAttribute("role"); figure.removeAttribute("tabindex"); figure.removeAttribute("aria-label"); }
    }
    syncFigureRole(); if (sheetMq.addEventListener) sheetMq.addEventListener("change", syncFigureRole); else sheetMq.addListener(syncFigureRole);
    figure.addEventListener("click", function () { if (isSheet()) open(); });
    figure.addEventListener("keydown", function (e) { if ((e.key === "Enter" || e.key === " ") && isSheet()) { e.preventDefault(); open(); } });
    picker.addEventListener("change", function (e) {
      if (e.target.name === "direction") { apply(e.target.value, true); if (isSheet()) close(); }
      if (e.target.name === "speed") setSpeed(parseFloat(e.target.value), true);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") { close(); return; }
      if (e.target.closest("textarea, select, [contenteditable], input:not([type=radio]):not([type=checkbox]):not([type=button])")) return;
      var n = parseInt(e.key, 10); if (n >= 1 && n <= DIRECTIONS.length) apply(DIRECTIONS[n - 1].id, true);
      if (e.key === "q" || e.key === "Q") { setSpeed(speed === 1 ? 0.25 : 1, true); document.getElementById(speed === 1 ? "speed-normal" : "speed-quarter").checked = true; }
    });
    document.getElementById(speed === 1 ? "speed-normal" : "speed-quarter").checked = true;
  }

  // ---------- lifecycle ----------
  document.addEventListener("visibilitychange", function () { visible = !document.hidden; start(); });
  if ("IntersectionObserver" in window) {
    new IntersectionObserver(function (es) { inView = es[0].isIntersecting; start(); }, { threshold: 0.05 }).observe(canvas);
  }
  window.addEventListener("resize", function () { if (reduced.matches) drawStill(); });
  reduced.addEventListener && reduced.addEventListener("change", start);

  buildPicker();
  var initial = params.get("d") || store.get("entangle.direction") || "singlet";
  apply(initial, false);
})();
