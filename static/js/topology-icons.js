/* The scan diagram's icon set and the three small helpers that choose an icon / a dot colour, shared by the PDF report page (scan_report.html).
   COPIED from templates/scan_detail.html (the same text also lives in vuln_scan_detail.html and network_topology.html): change the icons in all of
   them together. The report loads this file instead of carrying a fourth inline copy; moving the other pages onto it is a possible clean-up.
   Exposes window.TopologyIcons = { ICON_URI, CORE_NETWORK_ICON, osIconKey, vmIconKey, portDotColor }. */
(function (global) {
'use strict';

const CISCO_ICONS = {

    // ── Generic PC / Workstation ──────────────────────────────────────────────
    pc: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70"><g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="12" y="6" width="56" height="38" rx="3.5" fill="#eaf5fc"/><path d="M35 44 L45 44 L47.5 53 L32.5 53 Z" fill="#d6ecf8" stroke-width="1.8"/><rect x="25" y="53" width="30" height="4.5" rx="2.25" fill="#d6ecf8" stroke-width="1.8"/></g><path d="M20 36 L33 14 M27 36 L40 14" stroke="#ffffff" stroke-width="3" stroke-linecap="round" opacity=".75" fill="none"/><rect x="17" y="11" width="46" height="28" rx="1.5" fill="none" stroke="#4a9fd4" stroke-width="1.2" opacity=".55"/></svg>`,

    // ── Windows ───────────────────────────────────────────────────────────────
    windows: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70"><g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="12" y="6" width="56" height="38" rx="3.5" fill="#eaf5fc"/><path d="M35 44 L45 44 L47.5 53 L32.5 53 Z" fill="#d6ecf8" stroke-width="1.8"/><rect x="25" y="53" width="30" height="4.5" rx="2.25" fill="#d6ecf8" stroke-width="1.8"/></g><g fill="#4a9fd4" stroke="none"><rect x="30.5" y="15.5" width="9" height="9"/><rect x="30.5" y="25.5" width="9" height="9"/><rect x="40.5" y="15.5" width="9" height="9"/><rect x="40.5" y="25.5" width="9" height="9"/></g></svg>`,

    // ── Linux / Tux Penguin ───────────────────────────────────────────────────
    linux: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g transform="translate(40,38) scale(0.72)" fill="none" stroke="#4a9fd4" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
  <ellipse cx="0" cy="18" rx="28" ry="36" fill="#d6ecf8" stroke="#4a9fd4"/>
  <ellipse cx="0" cy="22" rx="17" ry="26" fill="#ffffff" stroke="#4a9fd4" stroke-width="1.3"/>
  <ellipse cx="0" cy="-18" rx="22" ry="22" fill="#d6ecf8" stroke="#4a9fd4"/>
  <ellipse cx="0" cy="-14" rx="13" ry="14" fill="#ffffff" stroke="#4a9fd4" stroke-width="1.3"/>
  <circle cx="-8" cy="-22" r="3.5" fill="#4a9fd4" stroke="none"/>
  <circle cx="-9" cy="-23" r="1" fill="#ffffff" stroke="none"/>
  <circle cx="8" cy="-22" r="3.5" fill="#4a9fd4" stroke="none"/>
  <circle cx="7" cy="-23" r="1" fill="#ffffff" stroke="none"/>
  <path d="M-5 -8 Q0 -3 5 -8 Q3 -12 -3 -12 Z" fill="#f0a500" stroke="#c87800" stroke-width="1.2"/>
  <path d="M-28 -6 Q-42 6 -28 28 Q-18 14 -18 -2 Z" fill="#d6ecf8" stroke="#4a9fd4"/>
  <path d="M28 -6 Q42 6 28 28 Q18 14 18 -2 Z" fill="#d6ecf8" stroke="#4a9fd4"/>
  <path d="M-16 52 Q-22 60 -28 57 Q-24 66 -14 64 Q-8 62 -6 54 Z" fill="#f0a500" stroke="#c87800" stroke-width="1.2"/>
  <path d="M16 52 Q22 60 28 57 Q24 66 14 64 Q8 62 6 54 Z" fill="#f0a500" stroke="#c87800" stroke-width="1.2"/>
  <path d="M0 -38 Q-3 -46 -4 -52 Q0 -44 4 -52 Q3 -46 0 -38Z" fill="#4a9fd4" stroke="none"/>
</g>
  </svg>`,

    // ── macOS ─────────────────────────────────────────────────────────────────
    mac: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <!-- iMac thin display -->
  <rect x="6" y="4" width="52" height="38" rx="4"/>
  <rect x="11" y="9" width="42" height="28" rx="2" fill="#d6ecf8" stroke="#4a9fd4" stroke-width="1.4"/>
  <!-- Apple logo: the standard glyph (24-unit grid) scaled .85 and centred on the screen (32, 23) -->
  <path transform="translate(32 23) scale(.85) translate(-12 -12)" d="M12.152 6.896c-.948 0-2.415-1.078-3.96-1.04-2.04.027-3.91 1.183-4.961 3.014-2.117 3.675-.546 9.103 1.519 12.09 1.013 1.454 2.208 3.09 3.792 3.039 1.52-.065 2.09-.987 3.935-.987 1.831 0 2.35.987 3.96.948 1.637-.026 2.676-1.48 3.676-2.948 1.156-1.688 1.636-3.325 1.662-3.415-.039-.013-3.182-1.221-3.22-4.857-.026-3.04 2.48-4.494 2.597-4.559-1.429-2.09-3.623-2.324-4.39-2.376-2-.156-3.675 1.09-4.61 1.09zM15.53 3.83c.843-1.012 1.4-2.427 1.245-3.83-1.207.052-2.662.805-3.532 1.818-.78.896-1.454 2.338-1.273 3.714 1.338.104 2.715-.688 3.559-1.701" fill="#4a9fd4" stroke="none"/>
  <!-- thin stand -->
  <path d="M32 42 L32 50 Q28 52 36 52" stroke-width="2"/>
  <!-- base oval -->
  <ellipse cx="32" cy="52" rx="12" ry="3"/>
</g>
  </svg>`,

    // ── Router / Cisco / Gateway ──────────────────────────────────────────────
    router: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <!-- cylinder body (router) -->
  <ellipse cx="32" cy="18" rx="22" ry="7"/>
  <line x1="10" y1="18" x2="10" y2="36"/>
  <line x1="54" y1="18" x2="54" y2="36"/>
  <ellipse cx="32" cy="36" rx="22" ry="7" fill="#d6ecf8" stroke="#4a9fd4" stroke-width="1.4"/>
  <!-- antennas -->
  <line x1="20" y1="18" x2="14" y2="4"/>
  <line x1="44" y1="18" x2="50" y2="4"/>
  <circle cx="14" cy="4" r="2" fill="#4a9fd4" stroke="none"/>
  <circle cx="50" cy="4" r="2" fill="#4a9fd4" stroke="none"/>
  <!-- port dots -->
  <circle cx="24" cy="36" r="2" fill="#4a9fd4" stroke="none"/>
  <circle cx="32" cy="36" r="2" fill="#4a9fd4" stroke="none"/>
  <circle cx="40" cy="36" r="2" fill="#4a9fd4" stroke="none"/>
</g>
  </svg>`,

    // ── Switch ────────────────────────────────────────────────────────────────
    switch: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <!-- switch box -->
  <rect x="6" y="22" width="52" height="22" rx="3"/>
  <!-- ports -->
  <rect x="12" y="28" width="6" height="10" rx="1" fill="#d6ecf8" stroke="#4a9fd4" stroke-width="1.4"/>
  <rect x="21" y="28" width="6" height="10" rx="1" fill="#d6ecf8" stroke="#4a9fd4" stroke-width="1.4"/>
  <rect x="30" y="28" width="6" height="10" rx="1" fill="#d6ecf8" stroke="#4a9fd4" stroke-width="1.4"/>
  <rect x="39" y="28" width="6" height="10" rx="1" fill="#d6ecf8" stroke="#4a9fd4" stroke-width="1.4"/>
  <!-- LED strip -->
  <circle cx="50" cy="30" r="1.5" fill="#4a9fd4" stroke="none"/>
  <circle cx="50" cy="35" r="1.5" fill="#4a9fd4" stroke="none"/>
  <circle cx="50" cy="40" r="1.5" fill="#4a9fd4" stroke="none"/>
  <!-- uplink cables -->
  <line x1="16" y1="22" x2="10" y2="10"/>
  <line x1="48" y1="22" x2="54" y2="10"/>
</g>
  </svg>`,

    // ── Android / Mobile ──────────────────────────────────────────────────────
    mobile: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="18" y="4" width="28" height="52" rx="5"/>
  <rect x="22" y="10" width="20" height="34" rx="1.5" fill="#d6ecf8" stroke="#4a9fd4" stroke-width="1.4"/>
  <!-- home button -->
  <circle cx="32" cy="50" r="3"/>
  <!-- speaker -->
  <line x1="28" y1="7" x2="36" y2="7"/>
</g>
  </svg>`,

    // ── Printer ───────────────────────────────────────────────────────────────
    printer: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="8" y="24" width="48" height="26" rx="3"/>
  <rect x="14" y="10" width="36" height="16" rx="2"/>
  <!-- paper out -->
  <rect x="16" y="38" width="32" height="18" rx="1.5" fill="#d6ecf8" stroke="#4a9fd4" stroke-width="1.4"/>
  <!-- lines on paper -->
  <line x1="20" y1="43" x2="44" y2="43" stroke-width="1.2"/>
  <line x1="20" y1="47" x2="44" y2="47" stroke-width="1.2"/>
  <!-- LED -->
  <circle cx="46" cy="30" r="2" fill="#4a9fd4" stroke="none"/>
</g>
  </svg>`,

    // ── Camera / IoT ──────────────────────────────────────────────────────────
    camera: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <path d="M8 20 L20 14 L20 54 L8 48 Z"/>
  <rect x="20" y="10" width="40" height="48" rx="4"/>
  <circle cx="40" cy="34" r="12" fill="#d6ecf8" stroke="#4a9fd4" stroke-width="1.6"/>
  <circle cx="40" cy="34" r="6" fill="#4a9fd4" stroke="none" opacity="0.35"/>
  <circle cx="40" cy="34" r="2.5" fill="#4a9fd4" stroke="none"/>
</g>
  </svg>`,

    // ── Unknown device ────────────────────────────────────────────────────────
    unknown: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="4" y="4" width="52" height="38" rx="4" fill="#d6ecf8" stroke="#4a9fd4"/>
  <rect x="10" y="10" width="40" height="26" rx="2" fill="#ffffff" stroke="#4a9fd4" stroke-width="1.4"/>
  <path d="M26 28 Q26 24 30 24 Q34 24 34 20 Q34 14 28 14 Q22 14 22 20" fill="none" stroke="#4a9fd4" stroke-width="2.5"/>
  <circle cx="28" cy="31" r="1.8" fill="#4a9fd4" stroke="none"/>
  <line x1="30" y1="42" x2="30" y2="50"/>
  <line x1="18" y1="50" x2="42" y2="50"/>
  <rect x="8" y="54" width="44" height="7" rx="2" fill="#d6ecf8" stroke="#4a9fd4"/>
  <rect x="2" y="2" width="56" height="62" rx="5" stroke="#4a9fd4" stroke-width="1.2" stroke-dasharray="4,3"/>
</g>
  </svg>`,

    // ── Virtual machine (identified from its MAC; no OS needed) ───────────────
    vm: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <rect x="4" y="4" width="52" height="38" rx="4" fill="#d6ecf8" stroke="#4a9fd4"/>
  <rect x="10" y="10" width="40" height="26" rx="2" fill="#ffffff" stroke="#4a9fd4" stroke-width="1.4"/>
  <text x="30" y="29" text-anchor="middle" font-family="monospace" font-size="15" font-weight="700" fill="#4a9fd4" stroke="none">VM</text>
  <line x1="30" y1="42" x2="30" y2="50"/>
  <line x1="18" y1="50" x2="42" y2="50"/>
  <rect x="8" y="54" width="44" height="7" rx="2" fill="#d6ecf8" stroke="#4a9fd4"/>
</g>
  </svg>`,

    // ── Gateway / router ───────────────────────────────────────────────────────
    gateway: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">
<g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
  <ellipse cx="32" cy="18" rx="22" ry="7"/>
  <line x1="10" y1="18" x2="10" y2="36"/><line x1="54" y1="18" x2="54" y2="36"/>
  <ellipse cx="32" cy="36" rx="22" ry="7" fill="#d6ecf8" stroke-width="1.4"/>
  <line x1="20" y1="18" x2="14" y2="4"/><line x1="44" y1="18" x2="50" y2="4"/>
  <circle cx="14" cy="4" r="2" fill="#4a9fd4" stroke="none"/><circle cx="50" cy="4" r="2" fill="#4a9fd4" stroke="none"/>
  <circle cx="24" cy="36" r="2" fill="#4a9fd4" stroke="none"/><circle cx="32" cy="36" r="2" fill="#4a9fd4" stroke="none"/><circle cx="40" cy="36" r="2" fill="#4a9fd4" stroke="none"/>
</g>
  </svg>`
};

function svgToDataUri(svgStr) {
    return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svgStr)));
}

// Pre-render all icons
const ICON_URI = {};
for (const [k, v] of Object.entries(CISCO_ICONS)) {
    ICON_URI[k] = svgToDataUri(v);
}
const CORE_NETWORK_ICON = svgToDataUri(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70"><g fill="none" stroke="#4a9fd4" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 44 Q10 44 10 38 Q10 30 18 30 Q18 22 26 20 Q34 14 44 20 Q52 18 56 26 Q64 26 64 36 Q64 44 56 44 Z" fill="#d6ecf8"/><path d="M28 56 Q32 50 40 50 Q48 50 52 56" stroke-width="2"/><path d="M32 62 Q36 58 40 58 Q44 58 48 62" stroke-width="2"/></g></svg>`);

function vmIconKey(device, key) { return device.vm && (key === 'unknown' || key === 'pc') ? 'vm' : key; }

function osIconKey(osStr) {
    if (!osStr) return 'unknown';     // no OS known: the "?" monitor, never a plain one
    const s = osStr.toLowerCase();
    if (s.includes('windows')) return 'windows';
    if (s.includes('android')) return 'mobile';      // before linux: "Android 12 (Linux 5.4)"
    if (s.includes('linux') || s.includes('ubuntu') || s.includes('debian') || s.includes('centos') || s.includes('fedora') || s.includes('kali')) return 'linux';
    if (s.includes('mac') || s.includes('darwin') || s.includes('macos') || s.includes('osx')) return 'mac';
    if (s.includes('switch')) return 'switch';
    if (s.includes('cisco') || s.includes('router')) return 'router';
    if (s.includes('android') || s.includes('ios') || s.includes('iphone') || s.includes('ipad') || s.includes('mobile')) return 'mobile';
    if (s.includes('printer')) return 'printer';
    if (s.includes('camera')) return 'camera';
    return 'unknown';
}

function portDotColor(portCount) {
    if (portCount <= 2) return '#2ecc71';   // green — < 3 ports / unknown
    if (portCount <= 6) return '#f1c40f';   // yellow — 3–6 ports
    return '#e74c3c';                          // red   — > 6 ports
}

global.TopologyIcons = { ICON_URI: ICON_URI, CORE_NETWORK_ICON: CORE_NETWORK_ICON, osIconKey: osIconKey, vmIconKey: vmIconKey, portDotColor: portDotColor };
})(window);
