/* The PDF report's network diagram as VECTOR (SVG), used only by templates/scan_report.html (2026-11-22).
 *
 * Why: the report used to draw the diagram with vis-network on a <canvas>, which a browser prints as ONE BITMAP. With hundreds of devices on one page
 * every icon is a few pixels and 500 lines meet at each router, so zooming in the PDF viewer only enlarges a blurry haze. Here the SAME layout (the
 * x / y that SubnetTopology.apply() gives every node, the same edges, the same icons, the same evidence rules for routers) is written as SVG: the icons are
 * <symbol>s drawn once and <use>d, the lines are paths, and every IP / router label is real, selectable, searchable text. Zoom in and it stays sharp.
 *
 * What it does NOT do: it has no layout of its own (the caller runs SubnetTopology.apply and hands over the nodes and edges), it draws no shadows and it
 * invents nothing (a router is drawn only when the node data says so, an unknown-ports dot is grey, a link with no router evidence is dashed).
 *
 * layout(input)  pure geometry, no DOM (so it can be tested under Node): boxes, label blocks, edge paths, bounds, the viewBox and some counts.
 * render(container, layout, options)  builds the <svg> with DOM calls only (createElementNS / setAttribute / textContent: nothing from a scan goes through innerHTML).
 * planCollapse(hosts, keyOf, limit)   which subnets to draw as one numbered bubble when there are too many devices to draw one by one.
 *
 * A node is the vis-network node object the report page already builds: { id, x, y, size, image (a data:image/svg+xml;base64 URI), font: { color, bold },
 * _lines: [{ text, dot?, mono? }], _collapsed, _count }. An edge: { from, to, width, dashes, smooth, color: { color, opacity } }. */
(function (global) {
  'use strict';

  var NS = 'http://www.w3.org/2000/svg';
  var MONO = '"JetBrains Mono", Consolas, "Courier New", monospace';
  var SANS = '"Sarabun", Tahoma, "Leelawadee UI", "Segoe UI", sans-serif';
  var FS = 12;                 // label font size in world units: the on-screen look of the old canvas at zoom 1 (12 px monospace)
  var ADV_MONO = 7.2, ADV_SANS = 6.4;   // a label's width is estimated from its character count (monospace is 0.6 em); the backing is a little wider than the text on purpose
  var LINE = 14.4;             // one label line
  var DOT_R = 4.2, DOT_ADV = 15.5;      // the port-count dot in front of an IP: its radius and the space it takes (the old "● " glyph)
  var PAD_X = 3, PAD_Y = 1.5, GAP = 4;  // label backing padding, and the gap between an icon and its label
  var FRAME_PAD = 14;          // free space around the drawing
  var DEFAULT_SIZE = 34;       // vis "size" of a device icon: the icon box is 2 x size wide (x 80/70 for these icons)
  var DEFAULT_RATIO = 80 / 70;

  function r1(n) { return Math.round(n * 10) / 10; }
  function r2(n) { return Math.round(n * 100) / 100; }
  function num(v, d) { v = +v; return isFinite(v) ? v : d; }

  // ---- icons: the data:image/svg+xml URIs of the shared icon set, decoded back to their SVG text ----
  var iconCache = {};
  function svgText(uri) {
    var m = /^data:image\/svg\+xml;base64,([A-Za-z0-9+\/=]+)$/.exec(String(uri || ''));
    if (!m) return '';
    try { return decodeURIComponent(escape(atob(m[1]))); } catch (e) { return ''; }
  }
  function iconInfo(uri) {
    if (iconCache[uri]) return iconCache[uri];
    var txt = svgText(uri), vb = /viewBox="\s*[-\d.]+[\s,]+[-\d.]+[\s,]+([\d.]+)[\s,]+([\d.]+)\s*"/.exec(txt), w = vb ? +vb[1] : 80, h = vb ? +vb[2] : 70;
    if (!(w > 0 && h > 0)) { w = 80; h = 70; }
    return (iconCache[uri] = { text: txt, w: w, h: h });
  }

  // ---- geometry ----
  function boxOf(n) {
    var size = num(n.size, DEFAULT_SIZE), box = { x: num(n.x, 0), y: num(n.y, 0), hw: size, hh: size, bubble: null, uri: '' };
    if (n._collapsed && num(n._count, 0) > 0) {                // a subnet drawn as one numbered bubble
      var count = Math.round(num(n._count, 0)), r = 34 + Math.min(14, Math.round(Math.sqrt(count) / 1.5));
      box.hw = r; box.hh = r; box.bubble = { r: r, count: count };
    } else if (n.image) {
      var ic = iconInfo(n.image), rw = ic.w > ic.h ? ic.w / ic.h : 1, rh = ic.h > ic.w ? ic.h / ic.w : 1;
      box.hw = size * rw; box.hh = size * rh; box.uri = n.image;     // the vis image shape: width 2 x size x ratio
    }
    return box;
  }
  function labelLines(n) {
    if (n._lines && n._lines.length) return n._lines;
    return String(n.label == null ? '' : n.label).replace(/<[^>]*>/g, '').split('\n').filter(function (t) { return t; }).map(function (t) { return { text: t }; });
  }
  function lineWidth(l) { return (l.dot ? DOT_ADV : 0) + String(l.text).length * (l.mono === false ? ADV_SANS : ADV_MONO); }
  function labelBox(box, lines) {
    if (!lines.length) return null;
    var w = 0; lines.forEach(function (l) { w = Math.max(w, lineWidth(l)); });
    w += 2 * PAD_X;
    var h = lines.length * LINE + 2 * PAD_Y;
    return { x: box.x - w / 2, y: box.y + box.hh + GAP, w: w, h: h };
  }
  // where a straight line from `a` toward `b` leaves a's rectangle (distance from a's centre)
  function border(n, ux, uy) { return Math.min(ux ? n.hw / Math.abs(ux) : Infinity, uy ? n.hh / Math.abs(uy) : Infinity); }
  function inside(p, n) { return Math.abs(p.x - n.x) <= n.hw && Math.abs(p.y - n.y) <= n.hh; }

  // vis-network's cubic Bezier edge: the control points of a "cubicBezier" line with the given roundness (the report's uplinks use .16)
  function via(a, b, roundness) {
    var dx = a.x - b.x, dy = a.y - b.y, x1, y1, x2, y2;
    if (Math.abs(dx) > Math.abs(dy)) { y1 = a.y; y2 = b.y; x1 = a.x - roundness * dx; x2 = b.x + roundness * dx; }
    else { y1 = a.y - roundness * dy; y2 = b.y + roundness * dy; x1 = a.x; x2 = b.x; }
    return [{ x: a.x, y: a.y }, { x: x1, y: y1 }, { x: x2, y: y2 }, { x: b.x, y: b.y }];
  }
  function lerp(p, q, t) { return { x: p.x + (q.x - p.x) * t, y: p.y + (q.y - p.y) * t }; }
  function splitCubic(P, t) {       // de Casteljau: [left, right]
    var a = lerp(P[0], P[1], t), b = lerp(P[1], P[2], t), c = lerp(P[2], P[3], t), d = lerp(a, b, t), e = lerp(b, c, t), f = lerp(d, e, t);
    return [[P[0], a, d, f], [f, e, c, P[3]]];
  }
  function cubicAt(P, t) { var u = 1 - t; return { x: u * u * u * P[0].x + 3 * u * u * t * P[1].x + 3 * u * t * t * P[2].x + t * t * t * P[3].x, y: u * u * u * P[0].y + 3 * u * u * t * P[1].y + 3 * u * t * t * P[2].y + t * t * t * P[3].y }; }
  // the parameter where the curve leaves `n` going away from the curve's `end` (0 = start node, 1 = end node); bisection on "is the point inside the box"
  function leave(P, n, fromStart) {
    var lo = 0, hi = 0.5;
    if (!fromStart) { lo = 1; hi = 0.5; }
    if (inside(cubicAt(P, hi), n)) return hi;       // the curve never leaves the box before its middle: nothing sensible to draw from this side
    for (var i = 0; i < 24; i++) {
      var mid = (lo + hi) / 2;
      if (inside(cubicAt(P, mid), n)) lo = mid; else hi = mid;
    }
    return hi;
  }
  function pt(p) { return r1(p.x) + ' ' + r1(p.y); }

  function layout(input) {
    var nodes = input.nodes || [], edges = input.edges || [], items = [], byId = {}, stats = { nodes: 0, bubbles: 0, edges: 0, dots: {}, dotted: 0 };
    nodes.forEach(function (n) {
      if (!n || !isFinite(+n.x) || !isFinite(+n.y)) return;
      var box = boxOf(n), lines = labelLines(n);
      var it = { id: n.id, box: box, lines: lines, label: labelBox(box, lines), color: (n.font && n.font.color) || '#343a40', bold: !!(n.font && n.font.bold === true) };
      items.push(it); byId[n.id] = it;
      stats.nodes++;
      if (box.bubble) stats.bubbles++;
      lines.forEach(function (l) { if (l.dot) { stats.dots[l.dot] = (stats.dots[l.dot] || 0) + 1; stats.dotted++; } });
    });
    // the world bounds: icons, bubbles and label blocks (the lines lie between them)
    var minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    items.forEach(function (it) {
      var b = it.box;
      minX = Math.min(minX, b.x - b.hw); maxX = Math.max(maxX, b.x + b.hw); minY = Math.min(minY, b.y - b.hh); maxY = Math.max(maxY, b.y + b.hh);
      if (it.label) { minX = Math.min(minX, it.label.x); maxX = Math.max(maxX, it.label.x + it.label.w); maxY = Math.max(maxY, it.label.y + it.label.h); }
    });
    if (!items.length) { minX = minY = 0; maxX = maxY = 1; }
    var bounds = { x: minX - FRAME_PAD, y: minY - FRAME_PAD, w: maxX - minX + 2 * FRAME_PAD, h: maxY - minY + 2 * FRAME_PAD };
    // the same rule as the old canvas (vis fit never zooms in past 1 css px per unit): a small diagram keeps its size, a big one is scaled down to the frame
    var fw = num(input.frameW, 640), fh = num(input.frameH, 560), maxScale = num(input.maxScale, 1);
    if (!(fw > 0)) fw = 640; if (!(fh > 0)) fh = 560;
    var scale = Math.min(maxScale, fw / bounds.w, fh / bounds.h), vw = fw / scale, vh = fh / scale;
    var cx = bounds.x + bounds.w / 2, cy = bounds.y + bounds.h / 2;
    // A viewer draws a line thinner than one device pixel as a one-pixel line, so a diagram scaled far down (hundreds of devices on one page) would show the lines of a router much heavier
    // than they are (the old bitmap blurred them away). The device lines are therefore drawn lighter the more the diagram is scaled down; zoomed in, they are what the layout says.
    var thin = 0.5 + 0.5 * Math.min(1, scale / 0.5);
    // edges grouped by style: a few paths instead of thousands of elements (the line colours are the shared engine's own)
    var groups = {}, order = [];
    edges.forEach(function (e) {
      var a = byId[e.from], b = byId[e.to];
      if (!a || !b) return;                              // an end that was not drawn (a device inside a bubble): no line
      var col = e.color && typeof e.color === 'object' ? e.color : { color: e.color }, dashed = !!e.dashes, width = num(e.width, 1.2), stroke = col.color || '#b9c2ca', opacity = num(col.opacity, 1);
      if (e._edgeRole === 'host') opacity = r2(opacity * thin);
      var d;
      if (e.smooth && typeof e.smooth === 'object') {   // a curve: the uplink from the Internet to a subnet's router (or to the subnet itself)
        var P = via(a.box, b.box, num(e.smooth.roundness, 0.16)), t0 = leave(P, a.box, true), t1 = leave(P, b.box, false);
        if (!(t0 < t1)) return;
        var seg = splitCubic(P, t1)[0]; seg = splitCubic(seg, t0 / t1)[1];
        d = 'M' + pt(seg[0]) + 'C' + pt(seg[1]) + ' ' + pt(seg[2]) + ' ' + pt(seg[3]);
      } else {                                          // a straight line, cut at the two icon boxes
        var dx = b.box.x - a.box.x, dy = b.box.y - a.box.y, dist = Math.hypot(dx, dy);
        if (!dist) return;
        var ux = dx / dist, uy = dy / dist, ta = border(a.box, ux, uy), tb = border(b.box, -ux, -uy);
        if (ta + tb >= dist) return;                    // the two icons touch: no line to see
        d = 'M' + r1(a.box.x + ux * ta) + ' ' + r1(a.box.y + uy * ta) + 'L' + r1(b.box.x - ux * tb) + ' ' + r1(b.box.y - uy * tb);
      }
      var key = [stroke, width, opacity, dashed ? 1 : 0].join('|');
      if (!groups[key]) { groups[key] = { stroke: stroke, width: width, opacity: opacity, dashed: dashed, d: [] }; order.push(key); }
      groups[key].d.push(d);
      stats.edges++;
    });
    return { items: items, edgeGroups: order.map(function (k) { return groups[k]; }), bounds: bounds, scale: scale,
             viewBox: [r1(cx - vw / 2), r1(cy - vh / 2), r1(vw), r1(vh)], stats: stats };
  }

  // ---- DOM ----
  var TAGS = { g: 1, path: 1, rect: 1, circle: 1, ellipse: 1, line: 1, polyline: 1, polygon: 1, text: 1 };
  var ATTRS = { d: 1, x: 1, y: 1, cx: 1, cy: 1, r: 1, rx: 1, ry: 1, x1: 1, y1: 1, x2: 1, y2: 1, width: 1, height: 1, points: 1, transform: 1, fill: 1, stroke: 1, opacity: 1,
                'fill-opacity': 1, 'stroke-opacity': 1, 'stroke-width': 1, 'stroke-linecap': 1, 'stroke-linejoin': 1, 'stroke-dasharray': 1, 'text-anchor': 1,
                'font-family': 1, 'font-size': 1, 'font-weight': 1 };
  function el(name, attrs, parent) {
    var e = document.createElementNS(NS, name);
    if (attrs) Object.keys(attrs).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (parent) parent.appendChild(e);
    return e;
  }
  // copy the drawing elements of a (parsed) icon into a <symbol>: only known shapes and presentation attributes, so even a damaged icon string can add nothing else
  function copyShapes(src, dst) {
    for (var c = src.firstChild; c; c = c.nextSibling) {
      if (c.nodeType === 3 && c.parentNode && c.parentNode.nodeName === 'text') { dst.appendChild(document.createTextNode(c.nodeValue)); continue; }
      if (c.nodeType !== 1 || !TAGS[c.localName]) continue;
      var e = document.createElementNS(NS, c.localName);
      for (var i = 0; i < c.attributes.length; i++) { var a = c.attributes[i]; if (ATTRS[a.name]) e.setAttribute(a.name, a.value); }
      dst.appendChild(e);
      copyShapes(c, e);
    }
  }
  function render(container, L, options) {
    options = options || {};
    var svg = el('svg', { viewBox: L.viewBox.join(' '), preserveAspectRatio: 'xMidYMid meet', width: '100%', height: '100%', role: 'img' });
    svg.style.display = 'block';
    if (options.ariaLabel) svg.setAttribute('aria-label', options.ariaLabel);
    // one <symbol> per distinct icon, drawn once and <use>d
    var defs = el('defs', null, svg), ids = {}, nextId = 0;
    function symbolFor(uri) {
      if (ids[uri]) return ids[uri];
      var ic = iconInfo(uri), id = 'rd-i' + (nextId++), sym = el('symbol', { id: id, viewBox: '0 0 ' + ic.w + ' ' + ic.h }, defs);
      if (ic.text) {
        var doc = new DOMParser().parseFromString(ic.text, 'image/svg+xml');
        if (doc.documentElement && doc.documentElement.localName === 'svg' && !doc.querySelector('parsererror')) copyShapes(doc.documentElement, sym);
      }
      return (ids[uri] = id);
    }
    // 1 lines
    var gE = el('g', { fill: 'none', 'stroke-linecap': 'butt' }, svg);
    L.edgeGroups.forEach(function (g) {
      var p = el('path', { d: g.d.join(''), stroke: g.stroke, 'stroke-width': g.width }, gE);
      if (g.opacity < 1) p.setAttribute('stroke-opacity', g.opacity);
      if (g.dashed) p.setAttribute('stroke-dasharray', '7 6');
    });
    // 2 icons and bubbles
    var gI = el('g', null, svg);
    L.items.forEach(function (it) {
      var b = it.box;
      if (b.bubble) {
        var big = String(b.bubble.count).length;
        el('circle', { cx: r1(b.x), cy: r1(b.y), r: b.bubble.r, fill: '#eaf5fc', stroke: '#4a9fd4', 'stroke-width': 3 }, gI);
        el('circle', { cx: r1(b.x), cy: r1(b.y), r: b.bubble.r - 7, fill: 'none', stroke: '#4a9fd4', 'stroke-width': 1.3, 'stroke-dasharray': '3 4' }, gI);
        var t = el('text', { x: r1(b.x), y: r1(b.y + (big <= 2 ? 9 : big === 3 ? 8 : 6)), 'text-anchor': 'middle', 'font-family': SANS, 'font-weight': 700, 'font-size': big <= 2 ? 26 : big === 3 ? 22 : 17, fill: '#1e3a5f' }, gI);
        t.textContent = String(b.bubble.count);
      } else if (b.uri) {
        var u = el('use', { x: r1(b.x - b.hw), y: r1(b.y - b.hh), width: r1(2 * b.hw), height: r1(2 * b.hh) }, gI);
        u.setAttribute('href', '#' + symbolFor(b.uri));
      } else {
        el('circle', { cx: r1(b.x), cy: r1(b.y), r: Math.max(6, b.hw / 2), fill: '#d6ecf8', stroke: '#4a9fd4', 'stroke-width': 2 }, gI);
      }
    });
    // 3 label backings (opaque white, so a line that passes under a label is hidden), then 4 the text and dots on top of all of them
    var gB = el('g', { fill: '#ffffff' }, svg), gT = el('g', null, svg);
    L.items.forEach(function (it) {
      var lb = it.label;
      if (!lb) return;
      el('rect', { x: r1(lb.x), y: r1(lb.y), width: r1(lb.w), height: r1(lb.h), rx: 2 }, gB);
      var cx = it.box.x;
      it.lines.forEach(function (l, i) {
        var mono = l.mono !== false, w = lineWidth(l), left = cx - w / 2, cy = lb.y + PAD_Y + (i + 0.5) * LINE;
        if (l.dot) el('circle', { cx: r1(left + DOT_R + 0.6), cy: r1(cy), r: DOT_R, fill: l.dot, 'class': 'dot' }, gT);
        // a line with no dot is centred on its node by the browser itself (the width estimate is only for the backing); a dotted line starts after its dot
        var tx = el('text', { x: r1(l.dot ? left + DOT_ADV : cx), y: r1(cy + 0.36 * FS), 'font-family': mono ? MONO : SANS, 'font-size': FS, fill: it.color }, gT);
        if (!l.dot) tx.setAttribute('text-anchor', 'middle');
        if (it.bold && i === 0) tx.setAttribute('font-weight', 700);
        tx.textContent = String(l.text);
      });
    });
    container.textContent = '';
    container.appendChild(svg);
    return svg;
  }

  // Which subnets to draw as one numbered bubble when the scan has more devices than `limit`: the biggest ones (never a subnet of one device) until about `limit`
  // devices are drawn one by one. `keyOf(ip)` is the grouping the layout uses (SubnetTopology.groupKey). Nothing collapses at or under the limit.
  function planCollapse(hosts, keyOf, limit) {
    var total = hosts.length, plan = { collapsed: {}, total: total, drawn: total, hidden: 0, bubbles: 0 };
    if (!(limit > 0) || total <= limit) return plan;
    var sizes = {};
    hosts.forEach(function (h) { var k = keyOf(h && h.ip); sizes[k] = (sizes[k] || 0) + 1; });
    Object.keys(sizes).filter(function (k) { return sizes[k] > 1; }).sort(function (a, b) { return sizes[b] - sizes[a] || (a < b ? -1 : 1); }).forEach(function (k) {
      if (plan.drawn > limit) { plan.collapsed[k] = true; plan.drawn -= sizes[k]; plan.bubbles++; }
    });
    plan.hidden = total - plan.drawn;
    return plan;
  }

  global.ReportDiagramSvg = { layout: layout, render: render, planCollapse: planCollapse, FONT_SIZE: FS };
})(typeof window !== 'undefined' ? window : globalThis);
