/* Big-network helpers for the two scan report diagrams (scan_detail.html and vuln_scan_detail.html), 2026-11-16.
 *
 * The Network Topology page has its own copy of this logic inline (network_topology.html: planCollapse, bubbleIcon, styleBubbles, drawBadges ...);
 * if you change one, check the other. What this file does for a report page:
 *   - Group by /24 (default), /16 or None, remembered per user (localStorage), with a note when None would draw a lot of devices.
 *   - Collapses the biggest subnets into one numbered bubble so that about BUDGET devices are drawn one by one; the user's own
 *     choices (a "+" / "-" badge click or a double-click on a hub) win and are kept for this page in sessionStorage.
 *   - A "+" badge on a collapsed hub and a "-" badge on an open one (drawn on the canvas in afterDrawing, same geometry for click and hover).
 * A choice reloads the page (the report pages already did that for their old dropdown), then fits the subnet that was just opened.
 * Words come from window.BIGD_T (partials/_big_diagram_texts.html); the English text here is only the fallback.
 * Needs subnet-topology.js (groupKey, engine options collapsed / wideGroups). The canvas of these pages stays light, so the colours are light.
 */
(function (global) {
  'use strict';
  var BUDGET = 150, BADGE_R = 10, BADGE_MIN_R = 6, FADE_FROM = 0.25, FADE_TO = 0.35;

  function T(key, fallback) { var d = global.BIGD_T; return (d && d[key]) ? d[key] : fallback; }
  function fmt(text, values) { return String(text).replace(/\{(\w+)\}/g, function (m, k) { return values[k] !== undefined ? values[k] : m; }); }

  function bubbleIcon(count) {
    var txt = count >= 1000 ? (Math.round(count / 100) / 10) + 'k' : String(count), fs = txt.length >= 4 ? 34 : 42;
    var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" width="100" height="100">'
      + '<circle cx="50" cy="50" r="47" fill="#eaf5fc" stroke="#4a9fd4" stroke-width="3.5"/>'
      + '<circle cx="50" cy="50" r="40" fill="none" stroke="#4a9fd4" stroke-width="1.5" stroke-dasharray="3 4"/>'
      + '<text x="50" y="' + (50 + fs * 0.36) + '" text-anchor="middle" font-family="Segoe UI, Arial, sans-serif" font-weight="700" font-size="' + fs + '" fill="#1e3a5f">' + txt + '</text></svg>';
    return 'data:image/svg+xml;base64,' + btoa(svg);
  }

  function injectStyle() {
    if (document.getElementById('bigd-style')) return;
    var st = document.createElement('style');
    st.id = 'bigd-style';
    st.textContent =
      '.bigd-ctl{display:flex;align-items:center;gap:8px;flex-wrap:wrap}'
      + '.bigd-lbl{font-size:.74rem;color:rgba(255,255,255,.7);white-space:nowrap}'
      + '.bigd-seg{display:inline-flex;gap:2px;padding:2px;border-radius:9px;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.18)}'
      + '.bigd-seg button{border:0;background:transparent;color:#e2e8f0;font-size:.76rem;font-weight:600;padding:3px 10px;border-radius:7px;cursor:pointer}'
      + '.bigd-seg button:hover{background:rgba(255,255,255,.12)}'
      + '.bigd-seg button[aria-pressed="true"]{background:#fff;color:#1e293b}'
      + '.bigd-seg button:focus-visible{outline:2px solid #7dd3fc;outline-offset:1px}'
      + '.bigd-pill{font-size:.74rem;color:#e2e8f0;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.18);border-radius:20px;padding:3px 10px;white-space:nowrap}'
      + '.bigd-pill b{font-weight:700}'
      + '.bigd-note{padding:6px 16px;font-size:.78rem;background:#fff7e0;color:#92400e;border-bottom:1px solid #f3dfa6}'
      + '.bigd-hover div.vis-tooltip{display:none!important}';
    document.head.appendChild(st);
  }

  function create(opts) {
    var hosts = opts.hosts || [], container = opts.container, ST = global.SubnetTopology;
    var prefKey = 'clylar.report.group.' + (global.BIGD_USER || ''), sessKey = 'clylar.report.big.' + location.pathname;
    var prefix = 24;
    try { var g = localStorage.getItem(prefKey); if (g === 'none') prefix = 0; else if (g === '16') prefix = 16; } catch (e) { /* storage blocked: group by /24 */ }
    var st = { choice: {}, frozen: [], focus: '' };
    try {
      var raw = JSON.parse(sessionStorage.getItem(sessKey) || 'null');
      if (raw && raw.prefix === prefix) st = { choice: raw.choice || {}, frozen: raw.frozen || [], focus: raw.focus || '' };
    } catch (e) { /* damaged storage: start clean */ }
    function save() { try { sessionStorage.setItem(sessKey, JSON.stringify({ prefix: prefix, choice: st.choice, frozen: st.frozen, focus: st.focus })); } catch (e) { /* ignored */ } }
    var keyOf = function (ip) { return prefix ? ST.groupKey(ip, prefix) : 'all'; };

    // which subnets are one bubble: what the user chose wins, then the biggest others until about BUDGET devices are drawn
    var sizes = {}, collapsed = {};
    hosts.forEach(function (h) { var k = keyOf(h.ip); sizes[k] = (sizes[k] || 0) + 1; });
    if (prefix) {
      var drawn = hosts.length;
      Object.keys(sizes).forEach(function (k) { if (st.choice[k] === 'closed' && sizes[k] > 1) { collapsed[k] = true; drawn -= sizes[k]; } });
      Object.keys(sizes).filter(function (k) { return !collapsed[k] && st.choice[k] !== 'open' && sizes[k] > 1; })
        .sort(function (a, b) { return sizes[b] - sizes[a] || (a < b ? -1 : 1); })
        .forEach(function (k) { if (drawn > BUDGET) { collapsed[k] = true; drawn -= sizes[k]; } });
    }
    var collapsedCount = Object.keys(collapsed).reduce(function (t, k) { return t + sizes[k]; }, 0);
    var byUser = function (k) { return st.choice[k] === 'closed' && st.frozen.indexOf(k) < 0; };

    function toggle(key, open) {
      Object.keys(sizes).forEach(function (k) {      // every other subnet keeps the state it has now
        if (!(k in st.choice)) { st.choice[k] = collapsed[k] ? 'closed' : 'open'; st.frozen.push(k); }
      });
      st.frozen = st.frozen.filter(function (k) { return k !== key; });
      st.choice[key] = open ? 'open' : 'closed';
      st.focus = open ? key : '';
      save();
      location.reload();
    }
    function setGrouping(value) {
      try { localStorage.setItem(prefKey, value === 0 ? 'none' : String(value)); } catch (e) { /* ignored */ }
      try { sessionStorage.removeItem(sessKey); } catch (e) { /* ignored */ }
      location.reload();
    }

    // ── the hubs that can be opened or closed, and the "+" / "-" badge on them ──
    var network = null, hubs = [], badgeHover = null, hubHover = null;
    function geom(id) {
      var vn = network && network.body && network.body.nodes[id];
      if (!vn || !vn.options) return null;
      var scale = network.getScale(), size = vn.options.size || 30, rs = Math.max(BADGE_MIN_R, Math.min(BADGE_R, size * scale * 0.42));
      return { x: vn.x + size * 0.74, y: vn.y - size * 0.74, r: rs / scale, rs: rs };
    }
    function alpha(h) {
      if (!h.open || badgeHover === h.id || hubHover === h.id) return 1;
      return Math.max(0, Math.min(1, (network.getScale() - FADE_FROM) / (FADE_TO - FADE_FROM)));
    }
    function badgeAt(pt) {
      if (!pt || !network) return null;
      for (var i = 0; i < hubs.length; i++) {
        var g = alpha(hubs[i]) >= 0.5 && geom(hubs[i].id);
        if (g && Math.hypot(pt.x - g.x, pt.y - g.y) <= (g.rs + 3) / network.getScale()) return hubs[i];
      }
      return null;
    }
    function draw(ctx) {
      if (!network || !hubs.length) return;
      var scale = network.getScale();
      hubs.forEach(function (h) {
        var g = geom(h.id), al = alpha(h);
        if (!g || al < 0.03) return;
        var hot = badgeHover === h.id;
        ctx.save();
        ctx.globalAlpha = al;
        ctx.beginPath(); ctx.arc(g.x, g.y, g.r, 0, Math.PI * 2);
        ctx.fillStyle = hot ? '#dbeefa' : '#ffffff'; ctx.fill();
        ctx.lineWidth = 1.5 / scale; ctx.strokeStyle = '#4a9fd4'; ctx.stroke();
        var a = g.r * 0.5;
        ctx.lineWidth = 2 / scale; ctx.lineCap = 'round'; ctx.strokeStyle = '#1e3a5f';
        ctx.beginPath(); ctx.moveTo(g.x - a, g.y); ctx.lineTo(g.x + a, g.y);
        if (!h.open) { ctx.moveTo(g.x, g.y - a); ctx.lineTo(g.x, g.y + a); }
        ctx.stroke();
        ctx.restore();
      });
      var hot = badgeHover !== null && hubs.filter(function (h) { return h.id === badgeHover; })[0], g2 = hot && geom(badgeHover);
      if (g2) {      // the label beside the hovered badge, drawn last so no neighbouring badge covers it
        var text = hot.open ? T('badgeCollapse', 'Click to collapse') : T('badgeExpand', 'Click to expand'), px = 1 / scale;
        ctx.save();
        ctx.font = (12 * px) + 'px "IBM Plex Sans Thai", "Segoe UI", sans-serif';
        var w = ctx.measureText(text).width + 14 * px, hgt = 22 * px, x = g2.x + g2.r + 6 * px, y = g2.y - hgt / 2;
        ctx.fillStyle = 'rgba(30,41,59,.95)';
        ctx.beginPath(); if (ctx.roundRect) ctx.roundRect(x, y, w, hgt, 6 * px); else ctx.rect(x, y, w, hgt); ctx.fill();
        ctx.fillStyle = '#ffffff'; ctx.textBaseline = 'middle'; ctx.fillText(text, x + 7 * px, g2.y);
        ctx.restore();
      }
    }
    function setBadgeHover(id) {
      if (badgeHover === id) return;
      badgeHover = id;
      if (container) container.classList.toggle('bigd-hover', id !== null);
      if (network) network.redraw();
    }

    var api = {
      prefix: prefix,
      collapsed: collapsed,
      budget: BUDGET,
      // true for a device that sits inside a collapsed subnet: the page draws no node for it
      hidden: function (ip) { return !!collapsed[keyOf(ip)]; },
      // what the page adds to its SubnetTopology.apply() config
      engineConfig: function () { return { collapsed: collapsed, wideGroups: true }; },
      // a collapsed subnet's hub becomes a disc with its device count inside
      style: function (nodesData) {
        nodesData.forEach(function (n) {
          if (!n._collapsed || !(n._isSegment || n._isGateway)) return;
          n.image = bubbleIcon(n._count);
          n.size = 46 + Math.min(24, Math.round(Math.sqrt(n._count) * 2));
          var NL = String.fromCharCode(10), head = (n._isGateway ? T('router', 'Router') + ' ' + n._gwIp + ' · ' : '') + n._subnet;
          n.label = (n.label || '') + NL + fmt(T('nDevices', '{n} devices'), { n: n._count });
          n.title = [head, fmt(T('nDevices', '{n} devices'), { n: n._count }),
            byUser(n._subnet) ? '' : fmt(T('bubbleAuto', 'Collapsed automatically: at most {max} devices are drawn one by one'), { max: BUDGET }),
            T('bubbleHint', 'Click + or double-click to expand')].filter(Boolean).join(NL);
          n.font = Object.assign({}, n.font, { size: 15 });
        });
      },
      isHub: function (id) { return hubs.some(function (h) { return h.id === id; }); },
      attach: function (net, nodesData, subnets) {
        network = net;
        hubs = prefix ? (subnets || []).filter(function (s) { return s.count >= 2; }).map(function (s) { return { id: s.hubId, key: s.key, open: !s.collapsed }; }) : [];
        injectStyle();
        net.on('afterDrawing', draw);
        net.on('hoverNode', function (e) { if (hubs.some(function (h) { return h.id === e.node; })) { hubHover = e.node; net.redraw(); } });
        net.on('blurNode', function () { if (hubHover !== null) { hubHover = null; net.redraw(); } });
        net.on('doubleClick', function (p) {
          var id = (p.nodes || [])[0], h = hubs.filter(function (x) { return x.id === id; })[0];
          if (h) toggle(h.key, !h.open);
        });
        if (container) {
          container.addEventListener('mousemove', function (e) {
            if (!hubs.length || e.buttons) { if (badgeHover !== null && e.buttons) setBadgeHover(null); return; }
            var r = container.getBoundingClientRect(), h = badgeAt(net.DOMtoCanvas({ x: e.clientX - r.left, y: e.clientY - r.top }));
            setBadgeHover(h ? h.id : null);
          });
          container.addEventListener('mouseleave', function () { setBadgeHover(null); });
        }
      },
      // the page's own click handler calls this first: true = the click was on a badge and the page is reloading
      click: function (params) {
        var h = badgeAt(params && params.pointer && params.pointer.canvas);
        if (h) { toggle(h.key, !h.open); return true; }
        return false;
      },
      // after the page's own fit: zoom to the subnet that was just opened
      afterBuild: function (net, subnets, nodesData) {
        if (!st.focus) return;
        var key = st.focus, sn = (subnets || []).filter(function (s) { return s.key === key; })[0];
        st.focus = ''; save();
        if (!sn) return;
        var ids = [sn.hubId].concat(sn.members.map(function (i) { return i + 1; })).filter(function (id) { return net.body.nodes[id]; });
        setTimeout(function () { net.fit({ nodes: ids, animation: false }); }, 120);
      },
      // the "Group by" control and the "shown N / M" pill, built with DOM calls and textContent
      mountControl: function (el) {
        if (!el) return;
        injectStyle();
        var wrap = document.createElement('div'); wrap.className = 'bigd-ctl';
        var lbl = document.createElement('span'); lbl.className = 'bigd-lbl'; lbl.textContent = T('groupBy', 'Group By'); wrap.appendChild(lbl);
        var seg = document.createElement('div'); seg.className = 'bigd-seg'; seg.setAttribute('role', 'group'); seg.setAttribute('aria-label', T('groupBy', 'Group By'));
        [[24, '/24', T('group24Title', 'Group devices by /24 subnet')], [16, '/16', T('group16Title', 'Group devices by /16 subnet (fewer, larger groups)')],
         [0, T('groupNone', 'None'), T('groupNoneTitle', 'Show every device without splitting them into subnets')]].forEach(function (o) {
          var b = document.createElement('button'); b.type = 'button'; b.textContent = o[1]; b.title = o[2];
          b.setAttribute('aria-pressed', o[0] === prefix ? 'true' : 'false');
          b.addEventListener('click', function () { if (o[0] !== prefix) setGrouping(o[0]); });
          seg.appendChild(b);
        });
        wrap.appendChild(seg);
        if (collapsedCount) {
          var pill = document.createElement('span'); pill.className = 'bigd-pill';
          pill.textContent = T('shown', 'Shown:') + ' ' + (hosts.length - collapsedCount) + ' / ' + hosts.length;
          wrap.appendChild(pill);
        }
        el.textContent = '';
        el.appendChild(wrap);
        if (!prefix && hosts.length > BUDGET) {
          var header = el.closest('.card-header');
          if (header && header.parentNode) {
            var note = document.createElement('div'); note.className = 'bigd-note'; note.setAttribute('role', 'status');
            note.textContent = fmt(T('groupNoneSlow', 'All {n} devices are drawn at once, which may be slow. Grouping by subnet is recommended.'), { n: hosts.length });
            header.parentNode.insertBefore(note, header.nextSibling);
          }
        }
      }
    };
    return api;
  }

  global.SubnetTopologyBig = { create: create, bubbleIcon: bubbleIcon, BUDGET: BUDGET };
})(window);
