/* Shared subnet layout helper for vis-network diagrams. */
(function (global) {
  'use strict';

  function ipToNumber(ip) {
    var p = String(ip || '').split('.');
    if (p.length !== 4 || p.some(function (v) { return !/^\d+$/.test(v) || +v > 255; })) return null;
    return (+p[0]) * 16777216 + (+p[1]) * 65536 + (+p[2]) * 256 + (+p[3]);
  }
  function numberToIp(n) {
    return [Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256,
      Math.floor(n / 256) % 256, n % 256].join('.');
  }
  function groups(devices, prefix) {
    var size = Math.pow(2, 32 - prefix), map = {};
    devices.forEach(function (device, index) {
      var value = ipToNumber(device && device.ip), key = 'Other', net = Infinity;
      if (value !== null) { net = Math.floor(value / size) * size; key = numberToIp(net) + '/' + prefix; }
      if (!map[key]) map[key] = { key: key, net: net, members: [] };
      map[key].members.push(index);
    });
    return Object.keys(map).map(function (key) { return map[key]; }).sort(function (a, b) { return a.net - b.net; });
  }
  // The key of the subnet a device is drawn in, the same grouping apply() uses ('a.b.c.0/24'; 'Other' for an address that is not IPv4).
  function groupKey(ip, prefix) {
    var value = ipToNumber(ip);
    if (value === null) return 'Other';
    var size = Math.pow(2, 32 - prefix);
    return numberToIp(Math.floor(value / size) * size) + '/' + prefix;
  }
  // Every label sits on a tinted backing matching the active canvas, so a line passing behind a label stays hidden there.
  var LABEL_BG = 'rgba(255,255,255,.94)';
  // Lines are light: the structure should be readable, not heavy. A line only highlights while its device is hovered (see focusPath).
  var EDGE_HOST = { color: '#b9c2ca', highlight: '#64748b', hover: '#64748b', opacity: .9 };
  var EDGE_UPLINK = { color: '#aeb8c1', highlight: '#64748b', hover: '#64748b' };
  var EDGE_FOCUS = { color: '#64748b', highlight: '#64748b', hover: '#64748b' };
  // Dark canvas ("Midnight NOC") tokens: only used when callers pass { theme: 'dark' }.
  var DARK_PALETTE = {
    isDark: true,
    labelBg: 'rgba(14,22,33,.86)',
    strokeColor: '#0e1621',
    edgeHost: { color: '#384b66', highlight: '#7dd3fc', hover: '#7dd3fc', opacity: .88 },
    edgeUplink: { color: '#475e7d', highlight: '#7dd3fc', hover: '#7dd3fc' },
    edgeFocus: { color: '#5cd0ff', highlight: '#7dd3fc', hover: '#7dd3fc', opacity: 1 },
    edgeFocusWidth: 2.8,
    edgeFocusShadow: { enabled: true, color: 'rgba(56,189,248,.85)', size: 14, x: 0, y: 0 },
    nodeHoverShadow: { enabled: true, color: 'rgba(56,189,248,.90)', size: 24, x: 0, y: 0 },
    flatEdge: { color: '#384b66', highlight: '#5cd0ff', hover: '#5cd0ff' },
    dimEdgeColor: '#384b66',
    hubLabel: '#e2e8f0',
    hubShadow: 'rgba(56,189,248,.52)',
    segmentShadow: 'rgba(56,189,248,.34)'
  };
  var LIGHT_PALETTE = {
    isDark: false,
    labelBg: LABEL_BG,
    strokeColor: '#ffffff',
    edgeHost: EDGE_HOST,
    edgeUplink: EDGE_UPLINK,
    edgeFocus: EDGE_FOCUS,
    edgeFocusWidth: 1.8,
    edgeFocusShadow: false,
    nodeHoverShadow: null,
    flatEdge: { color: '#90a4ae', highlight: '#607d8b', hover: '#607d8b' },
    dimEdgeColor: '#b9c2ca',
    hubLabel: null,
    hubShadow: 'rgba(33,37,41,.24)',
    segmentShadow: 'rgba(33,37,41,.18)'
  };
  function themePalette(config) {
    return (config && (config.theme === 'dark' || config.dark)) ? DARK_PALETTE : LIGHT_PALETTE;
  }
  // By default vis-network makes a hovered edge 1.5px and a selected edge 2px thicker, which turns a fan of lines into a heavy mass
  // that covers the labels. The lines keep their own width; only the colour changes.
  function sameWidth(width) { return width; }
  function options(prefix, config) {
    var pal = themePalette(config);
    // The outline around the glyphs closes the small gaps the backing leaves between the parts of a label (the dot, the IP).
    var nodes = { font: { background: pal.labelBg, strokeWidth: 3, strokeColor: pal.strokeColor } }, edges = { hoverWidth: sameWidth, selectionWidth: sameWidth };
    if (+prefix) return { nodes: nodes, edges: edges, physics: { enabled: false }, layout: { improvedLayout: false }, interaction: { hover: true, zoomView: true, tooltipDelay: 300 } };
    return { nodes: nodes, edges: edges, physics: { solver: 'forceAtlas2Based', forceAtlas2Based: { gravitationalConstant: -130, springLength: 170, springConstant: .04, damping: .5 }, stabilization: { iterations: 200 } }, layout: { improvedLayout: true }, interaction: { hover: true, zoomView: true, tooltipDelay: 300 } };
  }
  // ── Star layout ──
  // Each router is the centre of its own star and its devices sit on a ring around it; with many devices they fill several rings.
  // A device needs about STAR_ARC pixels along a ring (its icon, and an IP label some 120px wide).
  var STAR_ARC = 135, STAR_MIN_RADIUS = 150, STAR_SINGLE_RING_MAX = 16;
  function ringPlan(count) {
    if (count < 1) return [];
    // Up to 16 devices stay on one ring that grows with their number, which is what a star looks like.
    if (count <= STAR_SINGLE_RING_MAX) return [{ r: Math.max(STAR_MIN_RADIUS, count * STAR_ARC / (2 * Math.PI)), n: count }];
    var caps = [], total = 0;
    while (total < count) {
      var r = 230 + caps.length * 160, cap = Math.floor(2 * Math.PI * r / STAR_ARC);
      caps.push({ r: r, cap: cap }); total += cap;
    }
    var left = count;
    return caps.map(function (ring, index) {
      // Share the devices between the rings in proportion to their room, so no ring is left nearly empty.
      var n = index === caps.length - 1 ? left : Math.max(0, Math.min(left, Math.round(count * ring.cap / total)));
      left -= n;
      return { r: ring.r, n: n };
    }).filter(function (ring) { return ring.n > 0; });
  }
  // A "star of stars" (an extended star): the Internet is the hub in the middle, every router sits around it, and each router is the
  // hub of its own star of devices. Sets x, y, radius and the device offsets (device index -> {x, y} from the router) of every group.
  // The biggest star goes below the Internet and the others are spread evenly around it; each router is as far out as its own
  // ring needs so the ring does not run into the Internet node, and the whole circle grows until no two stars touch.
  function layoutStar(result, gatewayFor, nodes) {
    result.forEach(function (subnet) {
      var gateway = gatewayFor(subnet), gatewayAt = gateway && gateway.hostIndex >= 0 ? gateway.hostIndex : -1;
      // the detected gateway is drawn as the router itself, so it takes no place on the ring
      subnet.ringMembers = subnet.collapsed ? [] : subnet.members.filter(function (member, i) { return i !== gatewayAt; });
      subnet.rings = ringPlan(subnet.ringMembers.length);
      subnet.radius = subnet.rings.length ? subnet.rings[subnet.rings.length - 1].r : (subnet.collapsed ? 70 : STAR_MIN_RADIUS);
    });
    var cloud = nodes.filter(function (item) { return item.id === 0; })[0];
    if (cloud) { cloud.x = 0; cloud.y = 0; }
    var order = result.slice().sort(function (a, b) { return b.radius - a.radius; });   // stable: ties keep the address order
    var clearance = 220, gap = 200;       // free space between a ring and the Internet node, and between two stars
    function place() {
      order.forEach(function (subnet, k) {
        var angle = Math.PI / 2 + k * 2 * Math.PI / order.length, distance = clearance + subnet.radius;
        subnet.x = Math.cos(angle) * distance; subnet.y = Math.sin(angle) * distance;
      });
    }
    function crowded() {
      for (var i = 0; i < order.length; i++) for (var j = i + 1; j < order.length; j++) {
        if (Math.hypot(order[i].x - order[j].x, order[i].y - order[j].y) < order[i].radius + order[j].radius + gap) return true;
      }
      return false;
    }
    place();
    for (var guard = 0; guard < 80 && crowded(); guard++) { clearance += 30; place(); }
    result.forEach(function (subnet) {
      // The gap between two devices on a ring is turned towards the Internet, so the uplink does not run through a device.
      var towardsInternet = Math.atan2(0 - subnet.y, 0 - subnet.x), at = 0;
      subnet.offsets = {};
      subnet.rings.forEach(function (ring) {
        var step = 2 * Math.PI / ring.n;
        for (var i = 0; i < ring.n; i++) {
          var angle = towardsInternet + step / 2 + i * step;
          subnet.offsets[subnet.ringMembers[at++]] = { x: Math.cos(angle) * ring.r, y: Math.sin(angle) * ring.r };
        }
      });
    });
  }
  // ── Which device is the router of a subnet? Only what the scan data (or this computer) actually shows ──
  // A router is named only on direct evidence, in this order:
  //   1. a virtual-router MAC on a scanned host (VRRP / HSRP / GLBP),
  //   2. this computer's own default gateway (its routing table), when it lies in the subnet,
  //   3. the router before the host on a traceroute, when the scan carries the hops,
  //   4. a host whose OS fingerprint names router firmware, when exactly one host in the subnet does.
  // Open ports, a router-maker's MAC vendor and an address ending in .1 are NOT evidence: servers, laptops and NAS boxes have them
  // too. Nothing is ever invented: with no evidence the answer is "no router" and the diagram draws the subnet itself.
  // Returns { ip, reason, hostIndex, evidence, inScan, note }; ip is '' when no router could be identified.
  var VIRTUAL_ROUTER_MACS = [
    { prefix: '00:00:5e:00:01', label: 'VRRP (IPv4) virtual router MAC', key: 'vmac_vrrp4' },
    { prefix: '00:00:5e:00:02', label: 'VRRP (IPv6) virtual router MAC', key: 'vmac_vrrp6' },
    { prefix: '00:00:0c:07:ac', label: 'Cisco HSRP v1 virtual router MAC', key: 'vmac_hsrp1' },
    { prefix: '00:00:0c:9f:f0', label: 'Cisco HSRP v2 virtual router MAC', key: 'vmac_hsrp2' },
    { prefix: '00:07:b4:00',    label: 'Cisco GLBP virtual router MAC', key: 'vmac_glbp' }
  ];
  // Firmware that only routers run. Not "gateway" (a VPN appliance or phone can be fingerprinted as one) and not "access point".
  var ROUTER_OS_WORDS = ['routeros', 'openwrt', 'dd-wrt', 'pfsense', 'opnsense', 'vyos', 'cisco ios', 'junos', 'fortios', 'mikrotik', 'router'];
  function ipInCidr(ip, cidr) {
    var parts = String(cidr || '').split('/'), base = ipToNumber(parts[0]), value = ipToNumber(ip), bits = +parts[1];
    if (base === null || value === null || !(bits >= 0 && bits <= 32)) return false;
    var size = Math.pow(2, 32 - bits);
    return Math.floor(value / size) === Math.floor(base / size);
  }
  function _st(key, fallback) {
    var dict = global.SUBNET_T;
    return (dict && dict[key]) ? dict[key] : fallback;
  }
  function detectGateway(hosts, systemGw, subnet) {
    var none = { ip: '', reason: '', hostIndex: -1, evidence: '', inScan: false, note: '' };
    if (!hosts || !hosts.length) return none;
    function inSubnet(ip) {
      if (subnet && /\//.test(String(subnet.key || ''))) return ipInCidr(ip, subnet.key);
      var count = {}, top = '';      // no subnet given: the /24 that most of the scanned hosts are in
      hosts.forEach(function (h) {
        var p = String(h.ip || '').split('.');
        if (p.length === 4 && h.ip !== '127.0.0.1') { var k = p.slice(0, 3).join('.'); count[k] = (count[k] || 0) + 1; }
      });
      Object.keys(count).forEach(function (k) { if (!top || count[k] > count[top]) top = k; });
      return !!top && String(ip).indexOf(top + '.') === 0;
    }
    function indexOfIp(ip) { for (var i = 0; i < hosts.length; i++) if (hosts[i].ip === ip) return i; return -1; }

    // 1. virtual router MAC
    for (var i = 0; i < hosts.length; i++) {
      var mac = String(hosts[i].mac || '').toLowerCase().replace(/-/g, ':');
      for (var v = 0; v < VIRTUAL_ROUTER_MACS.length; v++) {
        if (mac.indexOf(VIRTUAL_ROUTER_MACS[v].prefix) === 0) {
          return { ip: hosts[i].ip, reason: _st(VIRTUAL_ROUTER_MACS[v].key, VIRTUAL_ROUTER_MACS[v].label) + ' (' + hosts[i].mac + ')', hostIndex: i, evidence: 'virtual-mac', inScan: true, note: '' };
        }
      }
    }

    // 2. this computer's default gateway
    var sysIp = systemGw && systemGw.ip ? String(systemGw.ip).trim() : '';
    if (sysIp) {
      var metric = (systemGw.metric !== undefined && systemGw.metric < 9999) ? ' [' + _st('metric_tag', 'metric {n}').replace('{n}', String(systemGw.metric)) + ']' : '';
      var onlyLocalhost = hosts.every(function (h) { return h.ip === '127.0.0.1'; });
      if (onlyLocalhost) {
        return { ip: sysIp, reason: _st('sys_gw', "This computer's default gateway (OS routing table)") + metric, hostIndex: -1, evidence: 'system-route', inScan: false,
                 note: _st('localhost_note', 'Shown for localhost: this computer reaches the network through it.') };
      }
      if (inSubnet(sysIp)) {
        var at = indexOfIp(sysIp);
        return { ip: sysIp, reason: _st('sys_gw', "This computer's default gateway (OS routing table)") + metric, hostIndex: at, evidence: 'system-route', inScan: at >= 0, note: '' };
      }
    }

    // 3. traceroute: the router just before the host, when it has an address in this subnet
    for (var t = 0; t < hosts.length; t++) {
      var hops = hosts[t].trace_hops || [];
      if (hops.length >= 2) {
        var pen = hops[hops.length - 2], penIp = pen && (pen.ipaddr || pen.ip);
        if (penIp && penIp !== hosts[t].ip && inSubnet(penIp)) {
          var penAt = indexOfIp(penIp);
          return { ip: penIp, reason: _st('trace_last', 'Last router before {ip} on the traceroute').replace('{ip}', hosts[t].ip), hostIndex: penAt, evidence: 'traceroute', inScan: penAt >= 0, note: '' };
        }
      }
    }

    // 4. router firmware in the OS fingerprint, only when it points at one host
    var candidates = [];
    hosts.forEach(function (h, idx) {
      var os = String(h.os || '').toLowerCase();
      if (h.ip !== '127.0.0.1' && os && ROUTER_OS_WORDS.some(function (w) { return os.indexOf(w) >= 0; })) candidates.push(idx);
    });
    if (candidates.length === 1) {
      var only = hosts[candidates[0]];
      return { ip: only.ip, reason: _st('router_os', 'Router OS fingerprint: {os}').replace('{os}', only.os), hostIndex: candidates[0], evidence: 'router-os', inScan: true, note: '' };
    }
    if (candidates.length > 1) {
      none.note = _st('multi_router', 'Possible routers ({n}): {ips}')
        .replace('{n}', String(candidates.length))
        .replace('{ips}', candidates.slice(0, 3).map(function (c) { return hosts[c].ip; }).join(', ') + (candidates.length > 3 ? ' +' + (candidates.length - 3) : ''));
    }
    return none;
  }

  // A subnet whose router is unknown is drawn as the network itself: a shared wire the devices hang on, not a device.
  function makeSegmentIcon(stroke, fill) {
    return 'data:image/svg+xml;base64,' + btoa('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 80 70" width="80" height="70">'
      + '<g fill="none" stroke="' + stroke + '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
      + '<rect x="10" y="29" width="60" height="12" rx="6" fill="' + fill + '"/>'
      + '<path d="M24 29V18M40 29V14M56 29V18M24 41v11M40 41v15M56 41v11"/></g>'
      + '<g fill="' + stroke + '"><circle cx="24" cy="16" r="2.6"/><circle cx="40" cy="12" r="2.6"/><circle cx="56" cy="16" r="2.6"/>'
      + '<circle cx="24" cy="54" r="2.6"/><circle cx="40" cy="58" r="2.6"/><circle cx="56" cy="54" r="2.6"/></g></svg>');
  }
  var SEGMENT_ICON = makeSegmentIcon('#4a9fd4', '#eaf5fc');
  var SEGMENT_ICON_DARK = makeSegmentIcon('#7dd3fc', '#123352');

  // How many columns the tree lays a subnet's devices in: at most 4 (the scan reports and every /24 are unchanged). With config.wideGroups (the
  // topology page) a group of more than 256 devices, which only a /16 or wider can be, gets up to 24 columns (about as wide as tall: rows are closer together than columns) so it opens as a block, not a strip.
  function columnsFor(count, wide) {
    var columns = Math.min(4, Math.max(1, Math.ceil(Math.sqrt(count))));
    if (wide && count > 256) columns = Math.min(24, Math.ceil(Math.sqrt(count)));
    return columns;
  }
  function apply(nodes, edges, devices, prefix, config) {
    var pal = themePalette(config);
    prefix = +prefix || 0;
    if (!prefix) {
      // Flat mode is the original diagram: Gateway connects directly to every
      // scanned host.  Do not leave the graph with nodes but no edges.
      devices.forEach(function (device, index) {
        if (!nodes.filter(function (item) { return item.id === index + 1; })[0]) return;
        var ports = (device && device.ports) || [];
        edges.push({ from: 0, to: index + 1, color: Object.assign({}, pal.flatEdge), width: 1.6, dashes: ports.length === 0, smooth: false, _edgeRole: 'flat' });
      });
      return [];
    }
    config = config || {};
    var palette = ['#212529','#343a40','#495057','#5c636a','#6c757d','#3f464d'];
    var result = groups(devices, prefix).map(function (group, index) {
      // config.collapsed = { '<subnet key>': true }: the caller drew no node for these devices, so the layouts must not leave room for them
      var total = group.members.length, collapsed = !!(config.collapsed && config.collapsed[group.key]), count = collapsed ? 0 : total;
      var columns = columnsFor(count, config.wideGroups);
      var rows = Math.ceil(count / columns), width = collapsed ? 130 : Math.max(240, columns * 125 + 60);
      var x = (index - (groups(devices, prefix).length - 1) / 2) * Math.max(300, width + 55);
      return { key: group.key, members: group.members, count: total, shown: count, collapsed: collapsed, x: x, y: -60, width: width, rows: rows,
        radius: collapsed ? 70 : Math.max(145, width / 2), color: palette[index % palette.length], hubId: devices.length + 1 + index };
    });
    // With config.collapsed (the topology page) the subnets are placed side by side by their own widths, so a wide subnet next to a narrow
    // bubble never overlaps it; without it the old even spacing is kept (the scan reports).
    if (config.collapsed && result.length) {
      var gapX = 55, sum = result.reduce(function (t, sn) { return t + sn.width; }, 0) + gapX * (result.length - 1), cursor = -sum / 2;
      result.forEach(function (sn) { sn.x = cursor + sn.width / 2; cursor += sn.width + gapX; });
    }
    var gatewayCache = {};
    function gatewayFor(subnet) {
      if (!gatewayCache[subnet.key]) {
        gatewayCache[subnet.key] = (typeof config.gatewayForGroup === 'function' && config.gatewayForGroup(subnet.members.map(function (i) { return devices[i]; }), subnet)) || {};
      }
      return gatewayCache[subnet.key];
    }
    var star = config.layout === 'star';
    if (star) layoutStar(result, gatewayFor, nodes);
    result.forEach(function (subnet) {
      var gateway = gatewayFor(subnet), known = !!(gateway && gateway.ip), NL = String.fromCharCode(10);
      nodes.push({ id: subnet.hubId, label: '', shape: 'dot', size: 24, x: subnet.x, y: subnet.y, fixed: { x: false, y: false },
                   font: { color: pal.hubLabel || subnet.color, size: 12, face: 'monospace', background: pal.labelBg }, _subnet: subnet.key, _count: subnet.count, _collapsed: subnet.collapsed, _lightFontColor: subnet.color });
      var hubNode = nodes[nodes.length - 1];
      if (known) {
        // A router that was identified from evidence (see detectGateway). A scanned host that is the router is drawn as the router.
        hubNode.label = _st('lbl_router', 'Router') + NL + gateway.ip;
        hubNode.image = config.gatewayIcon || config.hubIcon;
        hubNode.shape = hubNode.image ? 'image' : 'dot';
        hubNode.size = 36;
        hubNode.shadow = pal.isDark
          ? { enabled: true, color: pal.hubShadow, size: 22, x: 0, y: 0 }
          : { enabled: true, color: pal.hubShadow, size: 10 };
        hubNode._isGateway = true;
        hubNode._gwIp = gateway.ip;
        hubNode._gwReason = gateway.reason;
        hubNode._gwEvidence = gateway.evidence;
        hubNode._gwInScan = !!gateway.inScan;
        hubNode._gwNote = gateway.note || '';
        hubNode._device = gateway.hostIndex >= 0 ? devices[subnet.members[gateway.hostIndex]] : null;
        hubNode._portCnt = hubNode._device && hubNode._device.ports
          ? hubNode._device.ports.filter(function (p) { return String(p.state || '').toLowerCase() === 'open'; }).length : 0;
        hubNode._sortedPorts = hubNode._device && hubNode._device.ports
          ? hubNode._device.ports.slice().sort(function (a, b) { return (+a.port || 0) - (+b.port || 0); }) : [];
        hubNode.title = _st('lbl_router', 'Router') + NL + _st('tip_ip', 'IP: ') + gateway.ip + NL + _st('tip_subnet', 'Subnet: ') + subnet.key + NL + _st('tip_by', 'Identified by: ') + gateway.reason;
      } else {
        // No router could be identified, so none is drawn: the hub is the subnet itself (a network segment), not a device.
        hubNode.label = _st('lbl_subnet', 'Subnet') + NL + subnet.key;
        hubNode.image = config.segmentIcon || ((config.theme === 'dark' || config.dark) ? SEGMENT_ICON_DARK : SEGMENT_ICON);
        hubNode.shape = 'image';
        hubNode.size = 30;
        hubNode.shadow = pal.isDark
          ? { enabled: true, color: pal.segmentShadow, size: 14, x: 0, y: 0 }
          : { enabled: true, color: pal.segmentShadow, size: 8 };
        hubNode._isGateway = false;
        hubNode._isSegment = true;
        hubNode._note = gateway && gateway.note || '';
        hubNode._device = null;
        hubNode._portCnt = 0;
        hubNode._sortedPorts = [];
        hubNode.title = _st('lbl_subnet', 'Subnet') + ' ' + subnet.key + NL + _st('tip_count', 'Devices: {n}').replace('{n}', String(subnet.count)) + NL + _st('tip_no_router', 'No router identified')
          + (hubNode._note ? NL + hubNode._note : '');
      }

      // The router node owns the router host that was found among the scanned hosts. Remove that host's separate device node so
      // an address such as x.x.x.1 is not drawn twice.
      if (known && gateway.hostIndex >= 0) {
        var gatewayNodeId = subnet.members[gateway.hostIndex] + 1;
        var gatewayNodeIndex = nodes.findIndex(function (item) { return item.id === gatewayNodeId; });
        if (gatewayNodeIndex !== -1) nodes.splice(gatewayNodeIndex, 1);
      }
      // In the star the uplinks are the straight spokes of the big star; in the tree they are gentle curves. The link to the Internet
      // is dashed when no router was identified, because then nothing in the scan shows that this subnet is connected to it.
      edges.push({ from: 0, to: subnet.hubId, color: Object.assign({}, pal.edgeUplink), width: 1.8, smooth: star ? false : { type: 'cubicBezier', roundness: .16 },
                   dashes: known ? false : [7, 6], title: known ? '' : _st('edge_unverified', 'Link to the Internet not verified: no router was identified for this subnet'), _edgeRole: 'uplink' });
      subnet.members.forEach(function (deviceIndex, memberIndex) {
        // A detected gateway is already represented by this subnet's router
        // node.  Do not render its scanned-host node a second time.
        if (gateway && gateway.hostIndex >= 0 && deviceIndex === subnet.members[gateway.hostIndex]) return;
        var node = nodes.filter(function (item) { return item.id === deviceIndex + 1; })[0];
        if (!node) return;
        if (star && subnet.offsets[deviceIndex]) {
          node.x = subnet.x + subnet.offsets[deviceIndex].x;
          node.y = subnet.y + subnet.offsets[deviceIndex].y;
        } else {
          var columns = columnsFor(subnet.shown, config.wideGroups);
          var column = memberIndex % columns, row = Math.floor(memberIndex / columns);
          node.x = subnet.x + (column - (columns - 1) / 2) * 125;
          node.y = subnet.y + 145 + row * 115;
        }
        node.fixed = { x: false, y: false };
        edges.push({ from: subnet.hubId, to: deviceIndex + 1, color: Object.assign({}, pal.edgeHost), width: 1.2, dashes: false, smooth: false, _edgeRole: 'host' });
      });
    });
    return result;
  }
  // settings.float turns on the floating behaviour (see startFloat); without it a dragged router carries its hosts by hand.
  function attachRegions(network, getSubnets, settings) {
    network.__subnetGetter = getSubnets;
    var floating = !!(settings && settings.float);
    // The hover highlight (focusPath) is on unless the caller passes { highlight: false }; network.__setHighlight(on) switches it live.
    var highlightOn = !(settings && settings.highlight === false);
    var pal = themePalette(settings);
    network.__themePalette = pal;
    function region(subnet) {
      var ids = [subnet.hubId].concat(subnet.members.map(function (index) { return index + 1; }));
      var positions = network.getPositions(ids), hub = positions[subnet.hubId];
      if (!hub) return null;
      var radius = 0;
      ids.slice(1).forEach(function (id) {
        var point = positions[id];
        if (point) radius = Math.max(radius, Math.hypot(point.x - hub.x, point.y - hub.y));
      });
      return { x: hub.x, y: hub.y, radius: Math.max(subnet.radius, radius + 60) };
    }
    network.on('beforeDrawing', function (ctx) {
      return; // Groups are separated by hierarchy and alignment, not a boundary ring.
      (getSubnets() || []).forEach(function (subnet) {
        var box = region(subnet); if (!box) return;
        ctx.save(); ctx.beginPath(); ctx.arc(box.x, box.y, box.radius, 0, 2 * Math.PI);
        ctx.fillStyle = subnet.color + '12'; ctx.fill(); ctx.setLineDash([9, 7]); ctx.lineWidth = 2; ctx.strokeStyle = subnet.color + '99'; ctx.stroke();
        ctx.setLineDash([]); ctx.font = 'bold 15px monospace'; ctx.textAlign = 'center'; ctx.fillStyle = subnet.color;
        ctx.fillText(subnet.key + ' · ' + subnet.count + (subnet.count === 1 ? ' host' : ' hosts'), box.x, box.y - box.radius - 10); ctx.restore();
      });
    });

    // Drag a subnet hub: move its hosts by the same delta, so the dotted
    // subnet boundary and all member links stay together like Ntsubnet.
    var drag = null;
    network.on('dragStart', function (event) {
      drag = null;
      if (floating) return;      // the springs carry the hosts along (see startFloat)
      if (!event.nodes || event.nodes.length !== 1) return;
      var subnet = (getSubnets() || []).filter(function (item) { return item.hubId === event.nodes[0]; })[0];
      if (!subnet) return;
      var ids = [subnet.hubId].concat(subnet.members.map(function (index) { return index + 1; }));
      drag = { hubId: subnet.hubId, ids: ids, start: network.getPositions(ids), pointer: event.pointer && event.pointer.canvas ? { x: event.pointer.canvas.x, y: event.pointer.canvas.y } : null };
    });
    // The hosts are moved by setting their positions directly and asking for one redraw. network.moveNode() is not used here: every
    // call schedules its own full redraw, so a router with 100 hosts redrew 100 times for each mouse move and the drag crawled.
    function requestRedraw() {
      if (network.body && network.body.emitter) network.body.emitter.emit('_requestRedraw');   // vis merges these into one per frame
      else network.redraw();
    }
    function moveMembers(dx, dy) {
      if (!drag) return;
      drag.ids.forEach(function (id) {
        var node = network.body.nodes[id];
        if (id !== drag.hubId && node && drag.start[id]) { node.x = drag.start[id].x + dx; node.y = drag.start[id].y + dy; }
      });
      requestRedraw();
    }
    network.on('dragging', function (event) {
      if (!drag || !drag.pointer || !event.pointer || !event.pointer.canvas) return;
      moveMembers(event.pointer.canvas.x - drag.pointer.x, event.pointer.canvas.y - drag.pointer.y);
    });
    network.on('dragEnd', function () {
      if (!drag) return;
      var hub = network.getPositions([drag.hubId])[drag.hubId];
      if (hub && drag.start[drag.hubId]) moveMembers(hub.x - drag.start[drag.hubId].x, hub.y - drag.start[drag.hubId].y);
      drag = null;
    });

    // Hovering a device highlights its own line and the router's line up to the Internet, and fades every other line, so one path
    // can be followed in a busy diagram. Hovering a router does the same for all of its devices. Leaving restores the base lines.
    var baseStyle = null;
    var baseNodeShadow = null;
    var lastGlowNode = null;
    network.__resetThemeCache = function () {
      baseStyle = null;
      baseNodeShadow = null;
      lastGlowNode = null;
    };
    function focusPath(nodeId) {
      var curPal = network.__themePalette || pal;
      var data = network.body.data.edges, items = data.get(), keep = {};
      var nodeData = network.body.data.nodes;
      if (!baseStyle) {
        baseStyle = {};
        items.forEach(function (edge) { baseStyle[edge.id] = { color: edge.color, width: edge.width, shadow: edge.shadow || false }; });
      }
      if (!baseNodeShadow && nodeData) {
        baseNodeShadow = {};
        nodeData.get().forEach(function (n) { baseNodeShadow[n.id] = n.shadow || false; });
      }
      if (nodeId !== null) {
        items.forEach(function (edge) {
          if (edge.from !== nodeId && edge.to !== nodeId) return;
          keep[edge.id] = true;
          items.forEach(function (up) { if (up.to === edge.from) keep[up.id] = true; });     // the line above the router
        });
      }
      if (nodeData) {
        var nodeUpdates = [];
        if (lastGlowNode !== null && lastGlowNode !== nodeId && baseNodeShadow[lastGlowNode] !== undefined) {
          nodeUpdates.push({ id: lastGlowNode, shadow: baseNodeShadow[lastGlowNode] });
        }
        if (curPal.nodeHoverShadow && nodeId !== null && baseNodeShadow[nodeId] !== undefined) {
          nodeUpdates.push({ id: nodeId, shadow: curPal.nodeHoverShadow });
        }
        lastGlowNode = curPal.nodeHoverShadow ? nodeId : null;
        if (nodeUpdates.length) nodeData.update(nodeUpdates);
      }
      data.update(items.map(function (edge) {
        var base = baseStyle[edge.id] || { color: edge.color, width: edge.width, shadow: edge.shadow || false };
        if (nodeId === null) return { id: edge.id, color: base.color, width: base.width, shadow: base.shadow };
        if (keep[edge.id]) return { id: edge.id, color: Object.assign({}, curPal.edgeFocus), width: Math.max(base.width, curPal.edgeFocusWidth), shadow: curPal.edgeFocusShadow };
        return { id: edge.id, color: { color: typeof base.color === 'string' ? base.color : (base.color && base.color.color) || curPal.dimEdgeColor, opacity: .16 }, width: base.width, shadow: false };
      }));
    }
    // The highlight is not changed while a mouse button is held: restyling every line in the middle of a press or a drag only gets
    // in the way of the drag. It is brought up to date when the button is released.
    // "Reset position": every node goes back to where the layout drew it. Floating: the routers' places are reset and the springs
    // bring everything home. Otherwise the nodes are slid back by hand.
    var initial = {};
    network.body.nodeIndices.forEach(function (id) { var node = network.body.nodes[id]; initial[id] = { x: node.x, y: node.y }; });
    function slideTo(target) {
      var nodes = network.body.nodes, ids = Object.keys(target).filter(function (id) { return nodes[id]; }), from = {}, begin = null;
      ids.forEach(function (id) { from[id] = { x: nodes[id].x, y: nodes[id].y }; });
      function frame(now) {
        if (!network.body) return;
        begin = begin === null ? now : begin;
        var p = Math.min(1, (now - begin) / 450), e = p < .5 ? 2 * p * p : 1 - Math.pow(-2 * p + 2, 2) / 2;
        ids.forEach(function (id) { nodes[id].x = from[id].x + (target[id].x - from[id].x) * e; nodes[id].y = from[id].y + (target[id].y - from[id].y) * e; });
        requestRedraw();
        if (p < 1) requestAnimationFrame(frame);
      }
      requestAnimationFrame(frame);
    }
    network.__resetLayout = function () {
      if (network.__floatReset) network.__floatReset(initial); else slideTo(initial);
    };
    if (floating) startFloat(network, getSubnets);
    var hovered = null, pressed = false;
    function hoverTo(nodeId) { hovered = nodeId; if (!pressed && highlightOn) focusPath(nodeId); }
    // Off: every line goes back to its base style at once and hovering changes nothing. On: the device under the pointer is highlighted again.
    network.__setHighlight = function (on) { highlightOn = !!on; focusPath(highlightOn ? hovered : null); };
    network.on('hoverNode', function (event) { hoverTo(event.node); });
    network.on('blurNode', function () { hoverTo(null); });
    var frame = network.canvas && network.canvas.frame;
    if (frame) {
      frame.addEventListener('mousedown', function () {
        pressed = true;
        document.addEventListener('mouseup', function () { pressed = false; if (highlightOn) focusPath(hovered); }, { once: true });
      });
      // A node only follows the mouse while the button is held. vis-network ends a drag when it sees the button released, but it
      // can miss that (the browser cancels the press, the release lands somewhere else, the window loses focus), and then the node
      // keeps following the mouse after a plain click. So the drag is also ended when the pointer is cancelled, the window loses
      // focus, the button is released anywhere, or the mouse moves with no button down.
      var endStuckDrag = function (event) {
        var handler = network.interactionHandler;
        if (!handler || !handler.drag || !handler.drag.dragging) return;
        var at = event && event.clientX !== undefined ? { x: event.clientX, y: event.clientY } : { x: 0, y: 0 };
        try {
          network.body.eventListeners.onDragEnd({ center: at, srcEvent: event || {} });
        } catch (error) { handler.drag.dragging = false; }
        pressed = false;
      };
      frame.addEventListener('mousemove', function (event) { if (event.buttons === 0) endStuckDrag(event); }, true);
      // vis-network ends the drag itself on a normal release; this runs after it and only acts if the drag is somehow still on
      var afterRelease = function (event) { setTimeout(function () { endStuckDrag(event); }, 0); };
      var releaseEvents = ['pointerup', 'pointercancel', 'mouseup', 'blur'];
      releaseEvents.forEach(function (name) { window.addEventListener(name, afterRelease); });
      // the browser's own drag-and-drop would swallow the release
      frame.addEventListener('dragstart', function (event) { event.preventDefault(); });
      network.on('destroy', function () { releaseEvents.forEach(function (name) { window.removeEventListener(name, afterRelease); }); });
    }
  }
  // ── Floating behaviour, for the Tree and Star layouts alike ──
  // The layout decides where everything sits; this makes it float there, like balloons tethered on water. Each device is tied by a
  // spring to its place relative to its router (so it follows the router when that is dragged, a little late, and bounces), each
  // router by a weaker spring to its own place. The drift moves those places in slow, small circles. Devices push each other
  // apart when they get close, and the damping is low enough that a pulled device overshoots before it settles. The Internet node
  // is fixed and is not touched. vis-network's own physics stays off: it would lose the layout.
  //   k: spring stiffness (higher = snappier)   zeta: damping (0 = never stops, 1 = no bounce)   bob: drift radius in px
  var FLOAT_DEVICE = { k: 30, zeta: .45, bob: 4 }, FLOAT_ROUTER = { k: 14, zeta: .55, bob: 2 };
  var FLOAT_BOX = { w: 120, h: 96, push: 90 };      // a device's icon and label; how hard two overlapping ones push apart
  var FLOAT_COLLIDE_MAX = 250;                       // the pairwise check is skipped above this many devices
  function startFloat(network, getSubnets) {
    var reduced = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    var nodes = network.body.nodes, state = {}, dragged = {}, devices = [], raf = 0, last = 0;
    (getSubnets() || []).forEach(function (subnet) {
      var hub = nodes[subnet.hubId];
      if (!hub) return;
      state[subnet.hubId] = { router: true, vx: 0, vy: 0, hx: hub.x, hy: hub.y, phase: subnet.hubId * 1.7, cfg: FLOAT_ROUTER };
      subnet.members.forEach(function (index) {
        var node = nodes[index + 1];
        if (!node) return;       // the detected gateway is drawn as the router, so it has no node of its own
        state[index + 1] = { hub: subnet.hubId, ox: node.x - hub.x, oy: node.y - hub.y, vx: 0, vy: 0, phase: (index + 1) * 1.3, cfg: FLOAT_DEVICE };
        devices.push(index + 1);
      });
    });
    network.__floatReset = function (initial) {
      Object.keys(state).forEach(function (id) {
        var s = state[id];
        if (s.router && initial[id]) { s.hx = initial[id].x; s.hy = initial[id].y; }      // the devices follow their router
      });
    };
    network.__syncFloatTargets = function () {
      Object.keys(state).forEach(function (id) {
        var s = state[id], node = nodes[id];
        if (s.router && node) { s.hx = node.x; s.hy = node.y; }
      });
    };
    network.on('dragStart', function (event) {
      (event.nodes || []).forEach(function (id) { if (state[id]) { dragged[id] = true; state[id].px = undefined; } });
    });
    network.on('dragEnd', function () {
      Object.keys(dragged).forEach(function (id) {
        var s = state[id], node = nodes[id];
        if (s && s.router && node) { s.hx = node.x; s.hy = node.y; }      // a router stays where it is dropped; a device springs back
      });
      dragged = {};
    });
    function step(now) {
      raf = requestAnimationFrame(step);
      var dt = Math.min(.034, (now - last) / 1000);
      last = now;
      if (dt <= 0) return;
      var t = now / 1000, ids = Object.keys(state), accel = {}, moved = false;
      ids.forEach(function (id) {
        var s = state[id], node = nodes[id];
        if (!node) return;
        if (dragged[id]) {
          // held by the mouse: keep its speed, so it keeps going a little when let go
          if (s.px !== undefined) { s.vx = s.vx * .5 + (node.x - s.px) / dt * .5; s.vy = s.vy * .5 + (node.y - s.py) / dt * .5; }
          s.px = node.x; s.py = node.y;
          return;
        }
        var tx = s.router ? s.hx : nodes[s.hub].x + s.ox, ty = s.router ? s.hy : nodes[s.hub].y + s.oy;
        if (!reduced) { tx += Math.sin(t / 2.8 + s.phase) * s.cfg.bob; ty += Math.cos(t / 3.4 + s.phase * 1.3) * s.cfg.bob; }
        var c = 2 * s.cfg.zeta * Math.sqrt(s.cfg.k);
        accel[id] = { x: s.cfg.k * (tx - node.x) - c * s.vx, y: s.cfg.k * (ty - node.y) - c * s.vy };
      });
      if (devices.length <= FLOAT_COLLIDE_MAX) {
        for (var i = 0; i < devices.length; i++) {
          for (var j = i + 1; j < devices.length; j++) {
            var a = nodes[devices[i]], b = nodes[devices[j]];
            if (!a || !b) continue;
            var dx = b.x - a.x, dy = b.y - a.y;
            if (Math.abs(dx) > FLOAT_BOX.w || Math.abs(dy) > FLOAT_BOX.h) continue;
            var d = Math.hypot(dx / FLOAT_BOX.w, dy / FLOAT_BOX.h);
            if (d >= 1) continue;
            var len = Math.hypot(dx, dy) || 1, f = FLOAT_BOX.push * (1 - d) * 10, fx = dx / len * f, fy = dy / len * f;
            if (accel[devices[i]]) { accel[devices[i]].x -= fx; accel[devices[i]].y -= fy; }
            if (accel[devices[j]]) { accel[devices[j]].x += fx; accel[devices[j]].y += fy; }
          }
        }
      }
      ids.forEach(function (id) {
        var s = state[id], node = nodes[id], acc = accel[id];
        if (!node || !acc) return;
        s.vx += acc.x * dt; s.vy += acc.y * dt;
        var dx = s.vx * dt, dy = s.vy * dt;
        if (Math.abs(dx) < .005 && Math.abs(dy) < .005) return;
        node.x += dx; node.y += dy; moved = true;
      });
      if (moved || Object.keys(dragged).length) network.body.emitter.emit('_requestRedraw');
    }
    raf = requestAnimationFrame(function (now) { last = now; step(now); });
    network.on('destroy', function () { cancelAnimationFrame(raf); });
  }
  function setTheme(network, config) {
    if (!network || !network.body || !network.body.data) return;
    var pal = themePalette(config);
    network.__themePalette = pal;
    network.setOptions({ nodes: { font: { background: pal.labelBg, strokeColor: pal.strokeColor } } });
    var nodeData = network.body.data.nodes;
    if (nodeData) {
      var nodeUpdates = [];
      nodeData.get().forEach(function (n) {
        if (n._isGateway) {
          var gwFont = Object.assign({}, n.font || {}, { color: pal.hubLabel || n._lightFontColor || '#212529', background: pal.labelBg });
          nodeUpdates.push({
            id: n.id,
            image: (config && config.gatewayIcon) || n.image,
            font: gwFont,
            shadow: pal.isDark
              ? { enabled: true, color: pal.hubShadow, size: 22, x: 0, y: 0 }
              : { enabled: true, color: pal.hubShadow, size: 10 }
          });
        } else if (n._isSegment) {
          var segFont = Object.assign({}, n.font || {}, { color: pal.hubLabel || n._lightFontColor || '#212529', background: pal.labelBg });
          nodeUpdates.push({
            id: n.id,
            image: (config && config.segmentIcon) || (pal.isDark ? SEGMENT_ICON_DARK : SEGMENT_ICON),
            font: segFont,
            shadow: pal.isDark
              ? { enabled: true, color: pal.segmentShadow, size: 14, x: 0, y: 0 }
              : { enabled: true, color: pal.segmentShadow, size: 8 }
          });
        }
      });
      if (nodeUpdates.length) nodeData.update(nodeUpdates);
    }
    var edgeData = network.body.data.edges;
    if (edgeData) {
      var edgeUpdates = edgeData.get().map(function (e) {
        var roleColor = e._edgeRole === 'uplink' ? pal.edgeUplink : (e._edgeRole === 'flat' ? pal.flatEdge : pal.edgeHost);
        return { id: e.id, color: Object.assign({}, roleColor), shadow: false };
      });
      if (edgeUpdates.length) edgeData.update(edgeUpdates);
    }
    if (network.__resetThemeCache) network.__resetThemeCache();
  }
  function fit(network, animate) { network.fit({ animation: animate ? { duration: 450, easingFunction: 'easeInOutQuad' } : false }); }
  global.SubnetTopology = { apply: apply, visOptions: options, attachRegions: attachRegions, fit: fit, detectGateway: detectGateway, setTheme: setTheme, groupKey: groupKey };
})(window);
