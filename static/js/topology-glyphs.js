/* The flat line glyphs of the node pop-up header, shared by the two scan report pages (scan_detail.html, vuln_scan_detail.html).
 * The Network Topology page has the same set inline (network_topology.html: GLYPHS / osGlyph); if you change one, check the other.
 * They replace the emoji the report pop-ups used (they look different on every system). Every string here is fixed markup: no scan data
 * goes into it, so a page may set it with innerHTML. The glyph takes the header's text colour (currentColor).
 */
(function (global) {
  'use strict';
  var OPEN = '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';
  var GLYPHS = {
    windows: '<svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><rect x="3" y="3" width="8.4" height="8.4"/><rect x="12.6" y="3" width="8.4" height="8.4"/><rect x="3" y="12.6" width="8.4" height="8.4"/><rect x="12.6" y="12.6" width="8.4" height="8.4"/></svg>',
    apple: '<svg width="22" height="22" viewBox="-2 -2 28 28" fill="currentColor" aria-hidden="true"><path d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701"/></svg>',
    monitor: OPEN + '<rect x="3" y="4" width="18" height="12" rx="1.8"/><path d="M9.5 20h5M12 16v4"/></svg>',
    linux: OPEN + '<rect x="3" y="4" width="18" height="16" rx="2.2"/><path d="M7.5 9.5l3 2.5-3 2.5M12.5 15h4"/></svg>',
    router: OPEN + '<rect x="3" y="12" width="18" height="7" rx="2"/><path d="M7.5 15.5h.01M11 15.5h.01M7 12L5.5 6M17 12l1.5-6"/></svg>',
    phone: OPEN + '<rect x="7" y="3" width="10" height="18" rx="2.2"/><path d="M11 18h2"/></svg>',
    printer: OPEN + '<path d="M7 9V4h10v5M7 17H5a1.5 1.5 0 0 1-1.5-1.5v-5A1.5 1.5 0 0 1 5 9h14a1.5 1.5 0 0 1 1.5 1.5v5A1.5 1.5 0 0 1 19 17h-2"/><rect x="7" y="14" width="10" height="6"/></svg>',
    camera: OPEN + '<path d="M4 8h3l1.6-2.5h6.8L17 8h3a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9a1 1 0 0 1 1-1z"/><circle cx="12" cy="13" r="3.4"/></svg>',
    globe: OPEN + '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.6 2.7 3.8 5.7 3.8 9s-1.2 6.3-3.8 9c-2.6-2.7-3.8-5.7-3.8-9S8.2 5.7 12 3z"/></svg>'
  };
  // the glyph for an OS text, in the same order of checks the reports' header colour uses
  function osGlyph(osStr) {
    if (!osStr) return GLYPHS.monitor;
    var s = String(osStr).toLowerCase();
    if (s.indexOf('windows') >= 0) return GLYPHS.windows;
    if (s.indexOf('android') >= 0) return GLYPHS.phone;
    if (/linux|ubuntu|debian|centos|fedora|kali/.test(s)) return GLYPHS.linux;
    if (s.indexOf('mac') >= 0 || s.indexOf('darwin') >= 0) return GLYPHS.apple;
    if (/cisco|router|switch/.test(s)) return GLYPHS.router;
    if (/ios|iphone/.test(s)) return GLYPHS.phone;
    if (s.indexOf('printer') >= 0) return GLYPHS.printer;
    if (s.indexOf('camera') >= 0) return GLYPHS.camera;
    return GLYPHS.monitor;
  }
  global.TopoGlyphs = { GLYPHS: GLYPHS, osGlyph: osGlyph };
})(window);
