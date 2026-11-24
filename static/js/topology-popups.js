/* Several node pop-ups at once on the two scan report diagrams (scan_detail.html, vuln_scan_detail.html), 2026-11-17.
 * The page holds ONE pop-up in its markup (#node-popup, never shown): it is the template. Every device or router that is clicked gets its own
 * copy (a "card"); a second click on a node that already has a card only brings that card to the front, a click on empty canvas leaves all
 * of them open, and each closes with its own X (or Esc: the one used last). Cards are dragged by their header. The Network Topology page
 * does the same with cards it builds itself (network_topology.html: openNodePopup); this file is the report pages' version.
 *
 * Ids inside the template (popup-header, popup-ip, detail-tbody, port-tbody, panel-detail, panel-port, tab-detail, tab-port,
 * popup-drilldown-area) are turned into data-id="..." on a card, so the page never has two elements with the same id. A page fills a card
 * with card.q('popup-ip') and so on. The template's buttons call closePopup(this), the page's tab function(tab, this) and
 * openDrilldownFromPopup(this): all find their card with el.closest('.node-popup-card').
 *
 * Which device is this card about? Every open card and its device share a number: a small key-cap beside the device's IP label (drawn over the canvas,
 * the same size at every zoom; far out, where the label is not drawn, on the icon's top corner) and the same number in a chip at the start of the card's
 * header. While the mouse is over a card (or it is being dragged) the rest of the diagram fades to 88% and its device is drawn again on top at full colour,
 * with nothing added (spotlight by contrast only); hovering a device that has a card outlines that card and brings it forward.
 * Needs opts.network (the vis network) for that; opts.isHub(nodeId) says whether a node carries the +/- badge (its key-cap then uses the left corner when
 * it has to sit on the icon).
 */
(function (global) {
  'use strict';
  function create(opts) {
    var template = opts.template, container = opts.container, host = template.parentNode;
    var cards = {}, zTop = 10, drag = null, net = opts.network || null, hot = null;
    if (!document.getElementById('popups-style')) {
      var st = document.createElement('style');
      st.id = 'popups-style';
      st.textContent = '.node-popup-card.node-popup-hot{outline:2px solid rgba(37,99,235,.75)}.node-popup-card.node-popup-back{opacity:.7}.node-popup-card .np-pin{flex:none;width:22px;height:22px;border-radius:50%;background:#fff;color:#334155;font-weight:600;font-size:.75rem;line-height:22px;text-align:center;font-family:inherit}';
      document.head.appendChild(st);
    }
    function setHot(id) {
      if (hot === id) return;
      hot = id;
      Object.keys(cards).forEach(function (k) {
        var c = cards[k], me = id !== null && String(k) === String(id);
        c.classList.toggle('node-popup-hot', me);
        c.classList.toggle('node-popup-back', id !== null && !me);
      });
      if (net) net.redraw();
    }
    function nextNumber() {
      var used = {};
      Object.keys(cards).forEach(function (k) { used[cards[k]._num] = true; });
      var n = 1; while (used[n]) n++;
      return n;
    }
    // The icons are not drawn in the middle of their picture (a router's body sits in its upper left), so the halo and the pin are centred on the
    // visible part of the icon: its opaque pixels are measured once per picture (fractions of the picture), then scaled to the node.
    var contentCache = (typeof WeakMap === 'function') ? new WeakMap() : null;
    function measure(img) {
      var f = contentCache && contentCache.get(img);
      if (f) return f;
      f = { fx: 0.5, fy: 0.5, fw: 1, fh: 1 };
      try {
        var W = 128, c = document.createElement('canvas'); c.width = W; c.height = W;
        var x = c.getContext('2d'); x.drawImage(img, 0, 0, W, W);
        var d = x.getImageData(0, 0, W, W).data, a = W, b = -1, e = W, g = -1;
        for (var yy = 0; yy < W; yy++) for (var xx = 0; xx < W; xx++) if (d[(yy * W + xx) * 4 + 3] > 12) { if (xx < a) a = xx; if (xx > b) b = xx; if (yy < e) e = yy; if (yy > g) g = yy; }
        if (b >= a && g >= e) f = { fx: (a + b + 1) / 2 / W, fy: (e + g + 1) / 2 / W, fw: (b - a + 1) / W, fh: (g - e + 1) / W };
      } catch (err) { /* an image that cannot be read: the node's own centre is used */ }
      if (contentCache) contentCache.set(img, f);
      return f;
    }
    // { cx, cy, w, h }: the centre and the size of the VISIBLE part of the icon (world units)
    function contentOf(vn) {
      var size = vn.options.size || 30, img = vn.imageObj && vn.imageObj.image, cx = vn.x, cy = vn.y, w = size * 1.7, h = size * 1.7;
      if (img && img.width) {
        var f = measure(img);
        cx = vn.x + (f.fx - 0.5) * 2 * size; cy = vn.y + (f.fy - 0.5) * 2 * size; w = f.fw * 2 * size; h = f.fh * 2 * size;
      }
      return { cx: cx, cy: cy, w: w, h: h };
    }
    // The key-cap sits just left of the device's IP label (its last line), 14 px at every zoom. Far out, where a label is not drawn (or is tiny), it moves to
    // the icon's top corner instead (the top left one for a router or subnet, whose +/- badge is on the right).
    var LABEL_MIN_SCALE = 0.5;
    // The line of the label that holds the IP (the router's is the last of two, a "new" mark puts it first); lines come from vis-network's label module.
    function ipLineOf(L) {
      var lines = L && L.lines, i, j, t;
      if (!lines || !lines.length) return -1;
      for (i = 0; i < lines.length; i++) {
        t = ''; for (j = 0; j < (lines[i].blocks || []).length; j++) t += lines[i].blocks[j].text;
        if (/[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+/.test(t)) return i;
      }
      return lines.length - 1;
    }
    function keyCapPos(vn, cb, scale, hubSide) {
      var s = 14 / scale, L = vn.labelModule, ls = L && L.size, idx = ipLineOf(L);
      if (scale >= LABEL_MIN_SCALE && ls && ls.width > 0 && ls.height > 0 && idx >= 0) {
        var above = 0, k; for (k = 0; k < idx; k++) above += L.lines[k].height || 0;
        var line = L.lines[idx], lineW = line.width || ls.width, lineH = line.height || ls.height / L.lines.length;
        return { x: ls.left + ls.width / 2 - lineW / 2 - 4 / scale - s, y: ls.top + above + lineH / 2 - s / 2 + 1.5 / scale, s: s };
      }
      s = 15 / scale;
      var cornerX = cb.cx + hubSide * cb.w / 2, cornerY = cb.cy - cb.h / 2;
      return { x: cornerX - s / 2 + hubSide * 3 / scale, y: cornerY - s / 2 - 3 / scale, s: s };
    }
    function roundRect(ctx, x, y, w, h, r) {
      ctx.beginPath(); ctx.moveTo(x + r, y); ctx.lineTo(x + w - r, y); ctx.arcTo(x + w, y, x + w, y + r, r); ctx.lineTo(x + w, y + h - r); ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
      ctx.lineTo(x + r, y + h); ctx.arcTo(x, y + h, x, y + h - r, r); ctx.lineTo(x, y + r); ctx.arcTo(x, y, x + r, y, r); ctx.closePath();
    }
    // The spotlight (while a card is hovered) is contrast only: the rest of the diagram fades to 88% and the hovered device is drawn again on top, at full
    // colour and with nothing added (far out, where its icon would be tiny, it is drawn at least 22 px). Every open card also has a small number key-cap
    // beside its device's IP, accent blue for the hovered one. Drawn over the canvas in world coordinates in afterDrawing.
    function drawMarks(ctx) {
      if (!net) return;
      var ids = Object.keys(cards);
      if (!ids.length) return;
      var scale = net.getScale(), nodes = net.body && net.body.nodes, hv = hot !== null && cards[hot] && nodes[hot];
      if (hv && hv.options) {
        var tl = net.DOMtoCanvas({ x: 0, y: 0 }), br = net.DOMtoCanvas({ x: container.clientWidth, y: container.clientHeight }), hb = contentOf(hv);
        ctx.save();
        ctx.fillStyle = 'rgba(255,255,255,.88)'; ctx.fillRect(tl.x, tl.y, br.x - tl.x, br.y - tl.y);
        ctx.restore();
        var lift = Math.max(1, 22 / (Math.max(hb.w, hb.h) * scale));
        ctx.save();
        if (lift > 1) { ctx.translate(hb.cx, hb.cy); ctx.scale(lift, lift); ctx.translate(-hb.cx, -hb.cy); }
        try { hv.draw(ctx); } catch (e) { /* the node is simply not redrawn */ }
        ctx.restore();
      }
      ids.forEach(function (id) {
        var vn = nodes[id];
        if (!vn || !vn.options || vn.options.hidden) return;
        var cb = contentOf(vn), side = opts.isHub && opts.isHub(Number(id)) ? -1 : 1, isHot = hot !== null && String(hot) === String(id), k = keyCapPos(vn, cb, scale, side);
        ctx.save();
        ctx.globalAlpha = hot !== null && !isHot ? 0.4 : 1;
        roundRect(ctx, k.x, k.y, k.s, k.s, 4 / scale); ctx.fillStyle = isHot ? '#2563eb' : '#334155'; ctx.fill();
        ctx.fillStyle = '#ffffff'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        ctx.font = '600 ' + (k.s * 0.68) + 'px "IBM Plex Sans Thai", "Segoe UI", sans-serif';
        ctx.fillText(String(cards[id]._num), k.x + k.s / 2, k.y + k.s / 2 + 0.5 / scale);
        ctx.restore();
      });
    }
    if (net) {
      net.on('afterDrawing', drawMarks);
      net.on('hoverNode', function (e) { var c = cards[e.node]; if (c) { c.classList.add('node-popup-hot'); raise(c); } });
      net.on('blurNode', function () { Object.keys(cards).forEach(function (id) { if (String(id) !== String(hot)) cards[id].classList.remove('node-popup-hot'); }); });
    }

    function q(card, id) { return card.querySelector('[data-id="' + id + '"]'); }
    function cardOf(el) { return el && el.closest ? el.closest('.node-popup-card') : null; }
    function raise(card) { if (card) card.style.zIndex = String(++zTop); }
    function overlaps(left, top) {
      return Object.keys(cards).some(function (id) {
        var c = cards[id]; return Math.abs((parseFloat(c.style.left) || 0) - left) < 14 && Math.abs((parseFloat(c.style.top) || 0) - top) < 14;
      });
    }

    var api = {
      has: function (nodeId) { return !!cards[nodeId]; },
      raise: function (nodeId) { raise(cards[nodeId]); },
      count: function () { return Object.keys(cards).length; },
      // a new card for a node, placed beside the click (never exactly on top of an open one); the page fills it
      open: function (nodeId, point) {
        var card = template.cloneNode(true);
        card.removeAttribute('id');
        card.removeAttribute('aria-hidden');
        card.classList.add('node-popup-card');
        card.setAttribute('role', 'dialog');
        card.setAttribute('data-node', String(nodeId));
        Array.prototype.forEach.call(card.querySelectorAll('[id]'), function (el) { el.setAttribute('data-id', el.id); el.removeAttribute('id'); });
        var left = point.x + 16, top = point.y - 10, width = container.offsetWidth, height = container.offsetHeight;
        if (left + 390 > width) left = point.x - 390;
        if (left < 4) left = 4;
        if (top < 4) top = 4;
        if (top + 340 > height) top = height - 350;
        var guard = 0;
        while (overlaps(left, top) && guard++ < 12) { left += 26; top += 26; }
        if (left + 300 > width) left = Math.max(4, width - 304);
        if (top + 120 > height) top = Math.max(4, height - 124);
        card.style.left = left + 'px';
        card.style.top = top + 'px';
        card.style.display = 'block';
        var header = card.querySelector('[data-id="popup-header"]');
        card._num = nextNumber();
        if (header) { var chip = document.createElement('span'); chip.className = 'np-pin'; chip.setAttribute('aria-hidden', 'true'); chip.textContent = String(card._num); header.insertBefore(chip, header.firstChild); }
        host.appendChild(card);
        cards[nodeId] = card;
        raise(card);
        if (net) net.redraw();
        card.q = function (id) { return q(card, id); };
        return card;
      },
      // the X (this = the button), or a card itself
      close: function (el) {
        var card = cardOf(el) || el;
        if (!card || !card.getAttribute) return;
        var id = card.getAttribute('data-node');
        delete cards[id];
        if (hot !== null && String(hot) === id) setHot(null);
        if (card.parentNode) card.parentNode.removeChild(card);
        if (net) net.redraw();
        if (opts.onClose) opts.onClose(Number(id));
      },
      // switch the tab of the card that holds btn
      tab: function (tab, btn) {
        var card = cardOf(btn); if (!card) return;
        var isDetail = tab === 'detail';
        q(card, 'panel-detail').style.display = isDetail ? 'block' : 'none';
        q(card, 'panel-port').style.display = isDetail ? 'none' : 'block';
        q(card, 'tab-detail').style.background = isDetail ? '#e8e8e8' : '#fff';
        q(card, 'tab-port').style.background = isDetail ? '#fff' : '#e8e8e8';
      },
      ipOf: function (btn) { var card = cardOf(btn), el = card && q(card, 'popup-ip'); return el ? el.textContent : ''; }
    };

    // a press anywhere in a card brings it to the front; a press on its header starts a drag
    host.addEventListener('mousedown', function (e) {
      var card = cardOf(e.target);
      if (!card || !card.classList.contains('node-popup-card')) return;
      raise(card);
      var header = q(card, 'popup-header');
      if (!header || !header.contains(e.target) || e.target.closest('button')) return;
      drag = { card: card, x: e.clientX, y: e.clientY, left: parseFloat(card.style.left) || 0, top: parseFloat(card.style.top) || 0 };
      document.body.style.userSelect = 'none';
      e.preventDefault();
    });
    document.addEventListener('mousemove', function (e) {
      if (!drag) return;
      var parent = drag.card.offsetParent, maxLeft = parent ? parent.clientWidth - drag.card.offsetWidth : Infinity, maxTop = parent ? parent.clientHeight - drag.card.offsetHeight : Infinity;
      drag.card.style.left = Math.max(0, Math.min(drag.left + e.clientX - drag.x, maxLeft)) + 'px';
      drag.card.style.top = Math.max(0, Math.min(drag.top + e.clientY - drag.y, maxTop)) + 'px';
      if (hot !== null && net) net.redraw();      // the halo stays with the device, nothing else moves
    });
    document.addEventListener('mouseup', function (e) {
      if (!drag) return;
      drag = null; document.body.style.userSelect = '';
      if (!cardOf(e.target)) setHot(null);      // released outside every card: the pointer is no longer over it
    });
    host.addEventListener('mouseover', function (e) { var c = cardOf(e.target); if (c && c.classList.contains('node-popup-card')) setHot(Number(c.getAttribute('data-node'))); });
    host.addEventListener('mouseout', function (e) {
      var c = cardOf(e.target);
      if (c && !drag && !c.contains(e.relatedTarget)) setHot(null);
    });
    // Esc closes the card used last (unless a dialog is open: Esc belongs to it)
    document.addEventListener('keydown', function (e) {
      if (e.key !== 'Escape' || document.querySelector('.modal.show')) return;
      var top = null;
      Object.keys(cards).forEach(function (id) { if (!top || (parseInt(cards[id].style.zIndex, 10) || 0) > (parseInt(top.style.zIndex, 10) || 0)) top = cards[id]; });
      if (top) { api.close(top); e.preventDefault(); }
    });
    return api;
  }
  global.ReportPopups = { create: create };
})(window);
