'use strict';
/* =====================================================================
   ARCHITECTURE PAGE: one set of components and edges, three layouts.
   Columns   one column per zone, placed by hand in ARCH_POS.
   Bow-tie   whoever asks for a token, then Entra, then whatever accepts it.
   Hub       Entra in the centre, its helpers around it, every other zone in a ring.
   The bow-tie and hub positions are computed from ACTORS[id].zone, so a component
   added to ARCH_POS shows up in them without further edits.
   ===================================================================== */
const ARCH_VIEWS = [
  { id: 'columns', label: 'Columns', desc: 'One column per zone. Every connection is drawn. Select a component to highlight its own.' },
  { id: 'bowtie', label: 'Bow-tie', desc: 'Read it left to right. Clients and agents ask Entra for a token, Entra in the middle issues it, and resources on the right accept it. Faint dashed curves are calls made with a token. Select a component to highlight its connections.' },
  { id: 'hub', label: 'Hub and spoke', desc: 'Entra in the centre with the services it relies on around it. Every spoke is a token request. Faint dashed curves are calls made with a token. Select a component to highlight its connections.' },
];
const ARCH_EDGE_KINDS = [
  { id: 'token', label: 'Gets a token' },
  { id: 'call', label: 'Calls or uses with a token' },
  { id: 'trust', label: 'Trust or signal between identity services' },
];
// Clockwise from the top. Each zone sits next to the zones it talks to most, so few curves cross the hub.
const HUB_RING = ['people', 'agents', 'resources', 'apps'];
const HUB_ORDER = {
  people: ['device', 'user', 'browser', 'attacker', 'pc', 'partner', 'owner'],
  agents: ['agent', 'orchestrator', 'subagent', 'llm', 'mcpclient', 'foundry'],
  resources: ['mcpserver', 'downstream', 'search', 'workiq', 'm365', 'arm', 'fabric', 'graph'],
  apps: ['scimClient', 'daemon', 'azapp', 'workload', 'api', 'webapp'],
  identity: ['homeEntra', 'risk', 'intune', 'imds', 'idp'],
};
// Resources the agents column reaches most. They sit in the bow-tie's inner right column, nearest Entra.
const BOW_INNER = ['mcpserver', 'downstream', 'search', 'workiq'];

const archZoneOf = (id) => (ZONES.some((z) => z.id === ACTORS[id]?.zone) ? ACTORS[id].zone : 'apps');
const archZoneLabel = (zone) => ZONES.find((z) => z.id === zone)?.label || zone;
/** Components of one zone, in the preferred order, with anything not listed kept at the end in ARCH_POS order. */
function archZoneIds(zone, prefer = []) {
  const ids = Object.keys(ARCH_POS).filter((id) => archZoneOf(id) === zone);
  const rank = (id) => { const i = prefer.indexOf(id); return i < 0 ? prefer.length + ids.indexOf(id) : i; };
  return ids.sort((a, b) => rank(a) - rank(b));
}
const r1 = (v) => Math.round(v * 10) / 10;
const pts = (list) => list.map(([x, y]) => `${r1(x)},${r1(y)}`).join(' ');
const zoneText = (x, y, text, extra = '') => `<text class="zone-label" x="${r1(x)}" y="${r1(y)}" text-anchor="middle"${extra}>${esc(text)}</text>`;

function columnsLayout() {
  // Grow the canvas with the lowest node so every node stays inside its zone column.
  const W = 1180, H = Math.max(780, ...Object.values(ARCH_POS).map(([, y]) => y + NODE_H / 2 + 30));
  const bg = ZONES.map((z) => `<rect class="zone-rect" x="${z.x}" y="20" width="${z.w}" height="${H - 30}" rx="14"/>${zoneText(z.x + z.w / 2, 44, z.label)}`).join('');
  return { W, H, pos: ARCH_POS, order: Object.keys(ARCH_POS), bg };
}

/**
 * Bow-tie: three caller columns that narrow toward Entra, Entra and its helpers in the knot,
 * and two resource columns that widen again. The wing outlines are fitted around the nodes.
 */
function bowtieLayout() {
  const STEP = 110, MIN_GAP = NODE_H + 22, PAD = 14, LABEL = 24, HEAD = 40;
  const res = archZoneIds('resources');
  const cols = [
    { ids: archZoneIds('people'), x: 100, spread: 1, label: archZoneLabel('people') },
    { ids: archZoneIds('apps'), x: 310, spread: 0.8, label: archZoneLabel('apps') },
    { ids: archZoneIds('agents'), x: 520, spread: 0.62, label: archZoneLabel('agents') },
    { ids: res.filter((id) => BOW_INNER.includes(id)), x: 1000, spread: 0.62 },
    { ids: res.filter((id) => !BOW_INNER.includes(id)), x: 1210, spread: 1, label: archZoneLabel('resources') },
  ];
  const KNOT_X = 760, W = 1210 + NODE_W / 2 + 14;
  const full = Math.max(5 * STEP, ...cols.map((c) => (c.ids.length - 1) * STEP));
  const top = HEAD + PAD + LABEL + NODE_H / 2, cy = top + full / 2;
  const pos = {}, order = [];
  for (const c of cols) {
    const span = Math.max((c.ids.length - 1) * MIN_GAP, c.spread * full);
    const gap = c.ids.length > 1 ? span / (c.ids.length - 1) : 0;
    c.ids.forEach((id, i) => { pos[id] = [c.x, cy - span / 2 + i * gap]; });
    c.top = cy - span / 2 - NODE_H / 2 - (c.label ? LABEL : 0) - PAD;
    c.bottom = cy + span / 2 + NODE_H / 2 + PAD;
  }
  // The knot: Entra in the middle, half of its helpers above and half below.
  const helpers = archZoneIds('identity').filter((id) => id !== 'entra');
  const above = helpers.slice(0, Math.floor(helpers.length / 2)), below = helpers.slice(above.length);
  pos.entra = [KNOT_X, cy];
  above.forEach((id, i) => { pos[id] = [KNOT_X, cy - 120 - (above.length - 1 - i) * 90]; });
  below.forEach((id, i) => { pos[id] = [KNOT_X, cy + 120 + i * 90]; });
  const H = Math.max(...Object.values(pos).map(([, y]) => y)) + NODE_H / 2 + PAD + 20;
  // A wing is a trapezoid from its outer column to its inner one. Each edge leans as far in as the nodes allow.
  const wing = (wc, outer) => {
    const o = wc[outer], xo = outer === 0 ? o.x - NODE_W / 2 - PAD : o.x + NODE_W / 2 + PAD;
    const inner = wc[outer === 0 ? wc.length - 1 : 0], xi = outer === 0 ? inner.x + NODE_W / 2 + PAD : inner.x - NODE_W / 2 - PAD;
    let st = Infinity, sb = -Infinity;
    for (const c of wc) {
      for (const x of [c.x - NODE_W / 2 - PAD, c.x + NODE_W / 2 + PAD]) {
        const d = Math.abs(x - xo);
        if (d < 1) continue;
        st = Math.min(st, (c.top - o.top) / d); sb = Math.max(sb, (c.bottom - o.bottom) / d);
      }
    }
    if (!Number.isFinite(st)) { st = 0; sb = 0; }
    const D = Math.abs(xi - xo);
    return `<polygon class="zone-rect" points="${pts([[xo, o.top], [xi, o.top + st * D], [xi, o.bottom + sb * D], [xo, o.bottom]])}" stroke-linejoin="round"/>`;
  };
  const kTop = Math.min(...above.map((id) => pos[id][1]), cy) - NODE_H / 2 - LABEL - PAD;
  const kBottom = Math.max(...below.map((id) => pos[id][1]), cy) + NODE_H / 2 + PAD;
  const bg = [
    wing(cols.slice(0, 3), 0), wing(cols.slice(3), 1),
    `<rect class="zone-rect" x="${KNOT_X - NODE_W / 2 - PAD}" y="${r1(kTop)}" width="${NODE_W + 2 * PAD}" height="${r1(kBottom - kTop)}" rx="14"/>`,
    zoneText(KNOT_X, kTop + LABEL - 2, archZoneLabel('identity')),
    ...cols.filter((c) => c.label).map((c) => zoneText(c.x, c.top + PAD + LABEL - 10, c.label)),
    `<text class="arch-head" x="${(cols[0].x + cols[2].x) / 2}" y="24" text-anchor="middle">Ask for tokens →</text>`,
    `<text class="arch-head" x="${KNOT_X}" y="24" text-anchor="middle">Issue tokens</text>`,
    `<text class="arch-head" x="${(cols[3].x + cols[4].x) / 2}" y="24" text-anchor="middle">→ Accept tokens</text>`,
  ].join('');
  for (const c of cols.slice(0, 3)) order.push(...c.ids);
  order.push(...above, 'entra', ...below);
  for (const c of cols.slice(3)) order.push(...c.ids);
  return { W, H: r1(H), pos, order, bg, centre: pos.entra, curve: true };
}

/** Hub and spoke: helpers on a small ellipse around Entra, the other zones on a large one, each zone in its own slice. */
function hubLayout() {
  const helpers = archZoneIds('identity', HUB_ORDER.identity).filter((id) => id !== 'entra');
  const ring = HUB_RING.map((z) => ({ zone: z, ids: archZoneIds(z, HUB_ORDER[z]) })).filter((s) => s.ids.length);
  const outerIds = ring.flatMap((s) => s.ids);
  const IN_RX = 250, IN_RY = 135, ID_RX = 380, ID_RY = 200, M = 20, SEP_X = NODE_W + 12, SEP_Y = NODE_H + 12, GAP = 1;
  // "Box distance" in node sizes: two nodes do not overlap when it is at least 1.
  const dist = (a, b) => Math.max(Math.abs(a[0] - b[0]) / SEP_X, Math.abs(a[1] - b[1]) / SEP_Y);
  // Walk the ellipse clockwise from t0, putting each node at the first angle that is s box units clear of the
  // previous one (s + GAP between zones). Returns null when the ring does not close without overlapping.
  const walk = (rx, ry, s, t0) => {
    const at = (t) => [rx * Math.cos(t), ry * Math.sin(t)], end = t0 + 2 * Math.PI, out = [];
    let t = t0;
    for (const z of ring) {
      for (let i = 0; i < z.ids.length; i++) {
        if (out.length) {
          const prev = at(t), need = s + (i === 0 ? GAP : 0);
          do t += 0.002; while (dist(at(t), prev) < need && t < end);
        }
        out.push({ id: z.ids[i], t });
      }
    }
    const last = at(t);
    do t += 0.002; while (dist(at(t), last) < s + GAP && t < end + 1);
    return t <= end ? out.map((p) => ({ ...p, x: rx * Math.cos(p.t), y: ry * Math.sin(p.t) })) : null;
  };
  // Widest spacing that still closes the ring, so the slack is shared evenly instead of left in one gap.
  const fit = (rx, ry, t0) => {
    if (!walk(rx, ry, 1, t0)) return null;
    let lo = 1, hi = 3;
    for (let k = 0; k < 10; k++) { const mid = (lo + hi) / 2; if (walk(rx, ry, mid, t0)) lo = mid; else hi = mid; }
    return walk(rx, ry, lo, t0);
  };
  // Keep the width near a laptop screen and grow the height first (vertical scrolling is more natural than sideways
  // panning); then rotate the start so the first zone is centred at the top.
  let rx = ID_RX + NODE_W / 2 + 100, ry = ID_RY + NODE_H / 2 + 60, t0 = -Math.PI / 2, placed;
  for (let tries = 0; tries < 80 && !(placed = fit(rx, ry, t0)); tries++) { if (ry < rx * 0.9) ry *= 1.03; else { rx *= 1.03; ry *= 1.03; } }
  for (let k = 0; k < 3; k++) {
    const head = placed.slice(0, ring[0].ids.length), mid = (head[0].t + head[head.length - 1].t) / 2;
    t0 -= mid + Math.PI / 2;
    placed = fit(rx, ry, t0) || placed;
  }
  const ext = (k) => Math.max(...placed.map((p) => Math.abs(p[k])));
  const cx = M + ext('x') + NODE_W / 2, cy = M + 10 + ext('y') + NODE_H / 2;
  const W = 2 * cx, H = 2 * cy;
  const pos = { entra: [cx, cy] };
  helpers.forEach((id, i) => { const t = -Math.PI / 2 + (i / helpers.length) * 2 * Math.PI; pos[id] = [r1(cx + IN_RX * Math.cos(t)), r1(cy + IN_RY * Math.sin(t))]; });
  placed.forEach((p) => { pos[p.id] = [r1(cx + p.x), r1(cy + p.y)]; });
  // Slices run from the identity core out to the canvas edge. Their borders bend so they never cut a box: from the core to
  // just inside the gap between the last box of one zone and the first of the next, then straight out through that gap
  // (sideways where the two boxes are stacked, up or down where they sit side by side).
  const tOf = (id) => placed.find((p) => p.id === id);
  const X0 = -W / 2 + 6, X1 = W / 2 - 6, Y0 = -H / 2 + 6, Y1 = H / 2 - 6, w = X1 - X0, h = Y1 - Y0;
  const borders = ring.map((s, i) => {
    const a = tOf(s.ids[s.ids.length - 1]), b = tOf(ring[(i + 1) % ring.length].ids[0]);
    const gx = (a.x + b.x) / 2, gy = (a.y + b.y) / 2, sx = Math.sign(gx) || 1, sy = Math.sign(gy) || 1;
    const stacked = Math.abs(a.y - b.y) / SEP_Y >= Math.abs(a.x - b.x) / SEP_X;
    const inner = stacked ? [sx * (Math.min(Math.abs(a.x), Math.abs(b.x)) - NODE_W / 2 - 8), gy] : [gx, sy * (Math.min(Math.abs(a.y), Math.abs(b.y)) - NODE_H / 2 - 8)];
    const end = stacked ? [sx > 0 ? X1 : X0, gy] : [gx, sy > 0 ? Y1 : Y0];
    return { t: Math.atan2(inner[1] / ID_RY, inner[0] / ID_RX), inner, end };
  });
  // Canvas corners met when walking the edge clockwise from one border end to the next.
  const perim = ([x, y]) => (y === Y0 ? x - X0 : x === X1 ? w + y - Y0 : y === Y1 ? w + h + X1 - x : 2 * w + h + Y1 - y);
  const corners = [[0, [X0, Y0]], [w, [X1, Y0]], [w + h, [X1, Y1]], [2 * w + h, [X0, Y1]]];
  const between = (from, to) => {
    const s0 = perim(from); let s1 = perim(to);
    if (s1 <= s0) s1 += 2 * (w + h);
    return corners.flatMap(([s, c]) => [s, s + 2 * (w + h)].filter((v) => v > s0 && v < s1).map((v) => [v, c])).sort((p, q) => p[0] - q[0]).map((p) => p[1]);
  };
  const IR = 1.04, at = ([x, y]) => [cx + x, cy + y];
  const slices = ring.map((s, i) => {
    const prev = borders[(i - 1 + ring.length) % ring.length], cur = borders[i];
    let a = prev.t, b = cur.t;
    while (b <= a) b += 2 * Math.PI;
    const steps = Math.max(8, Math.ceil((b - a) / 0.03)), arc = [];
    for (let k = 0; k <= steps; k++) { const t = a + ((b - a) * k) / steps; arc.push([ID_RX * IR * Math.cos(t), ID_RY * IR * Math.sin(t)]); }
    const outline = [...arc, cur.inner, cur.end, ...between(prev.end, cur.end).reverse(), prev.end, prev.inner].map(at);
    const mid = (a + b) / 2, side = Math.abs(Math.cos(mid)) > 0.7;
    // Label in the gap between the identity ellipse and the ring: across the slice at the top and bottom, along it at the sides.
    const lx = cx + (ID_RX + (side ? 46 : 0)) * Math.cos(mid), ly = cy + (ID_RY + (side ? 0 : 52)) * Math.sin(mid);
    const rot = side ? ` transform="rotate(${Math.cos(mid) > 0 ? 90 : -90} ${r1(lx)} ${r1(ly)})"` : '';
    return `<polygon class="zone-rect hub-slice${i % 2 ? ' alt' : ''}" points="${pts(outline)}" stroke-linejoin="round"/>${zoneText(lx, ly + 4, archZoneLabel(s.zone), `${rot} paint-order="stroke"`)}`;
  }).join('');
  const bg = `${slices}<ellipse class="zone-rect hub-core" cx="${r1(cx)}" cy="${r1(cy)}" rx="${ID_RX}" ry="${ID_RY}"/>${zoneText(cx, cy - ID_RY + 26, archZoneLabel('identity'), ' paint-order="stroke"')}`;
  return { W: r1(W), H: r1(H), pos, order: ['entra', ...helpers, ...outerIds], bg, centre: [cx, cy], curve: true };
}

const ARCH_LAYOUTS = { columns: columnsLayout, bowtie: bowtieLayout, hub: hubLayout };

/** Edges to Entra are token requests, edges between identity services are trust or signals, the rest are calls. */
function archEdgeKind(a, b) {
  const ia = archZoneOf(a) === 'identity', ib = archZoneOf(b) === 'identity';
  return ia && ib ? 'trust' : ia || ib ? 'token' : 'call';
}
/** Token and trust edges run straight to the centre. Calls bow away from Entra so they skirt the hub instead of crossing it. */
function archEdgePath(a, b, L, kind) {
  const [x1, y1] = L.pos[a], [x2, y2] = L.pos[b];
  if (!L.curve || kind !== 'call') return `M${r1(x1)} ${r1(y1)}L${r1(x2)} ${r1(y2)}`;
  const mx = (x1 + x2) / 2, my = (y1 + y2) / 2, len = Math.hypot(x2 - x1, y2 - y1) || 1;
  let nx = -(y2 - y1) / len, ny = (x2 - x1) / len;
  if (nx * (mx - L.centre[0]) + ny * (my - L.centre[1]) < 0) { nx = -nx; ny = -ny; }
  const bend = Math.min(170, len * 0.32);
  const qx = Math.min(L.W - 8, Math.max(8, mx + nx * bend)), qy = Math.min(L.H - 8, Math.max(8, my + ny * bend));
  return `M${r1(x1)} ${r1(y1)}Q${r1(qx)} ${r1(qy)} ${r1(x2)} ${r1(y2)}`;
}

function archStoredView() {
  let v = APP.archView;
  if (!v) { try { v = localStorage.getItem('authflow-archview'); } catch { /* storage blocked */ } }
  return ARCH_VIEWS.some((x) => x.id === v) ? v : 'columns';
}
const edgeSample = (k) => `<svg width="34" height="10" aria-hidden="true" focusable="false"><path class="arch-edge ${k}" d="M2 5H32"/></svg>`;

/** Draw one layout into the existing SVG and keep the zoom, the selection and the tabs in step. */
function setArchView(view, user) {
  const v = ARCH_VIEWS.find((x) => x.id === view) || ARCH_VIEWS[0];
  APP.archView = v.id;
  if (user) { try { localStorage.setItem('authflow-archview', v.id); } catch { /* storage blocked */ } }
  const L = ARCH_LAYOUTS[v.id](), styled = v.id !== 'columns';
  const edges = ARCH_EDGES.filter(([a, b]) => L.pos[a] && L.pos[b]).map(([a, b]) => {
    const k = archEdgeKind(a, b);
    return `<path class="arch-edge${styled ? ` ${k}` : ''}" data-a="${a}" data-b="${b}" d="${archEdgePath(a, b, L, styled ? k : 'line')}"/>`;
  }).join('');
  const svg = $('#archSvg');
  svg.setAttribute('viewBox', `0 0 ${L.W} ${L.H}`);
  svg.dataset.view = v.id;
  svg.setAttribute('aria-label', `${v.label} layout: architecture diagram with ${L.order.length} components`);
  svg.innerHTML = `${L.bg}<g aria-hidden="true">${edges}</g><g>${L.order.map((id) => nodeSvg(id, L.pos[id][0], L.pos[id][1], 'clickable')).join('')}</g>`;
  fitSvgText(svg);
  $$('[data-arch-view]').forEach((b) => { const on = b.dataset.archView === v.id; b.setAttribute('aria-selected', on); b.tabIndex = on ? 0 : -1; });
  $('#archVp').setAttribute('aria-labelledby', `archTab-${v.id}`);
  $('#archDesc').textContent = v.desc;
  $('.edge-legend').hidden = !styled;
  markArchSelection();
  const vp = $('#archVp'); vp.scrollLeft = 0; vp.scrollTop = 0;
  // All three layouts share one zoom level, so switching layout keeps the scale the user chose.
  APP.archZoom.apply();
  if (user) announce(`${v.label} layout`);
}

function markArchSelection() {
  const id = APP.archSel, svg = $('#archSvg');
  svg.classList.toggle('has-sel', !!id);
  if (!id) return;
  $$('.node', svg).forEach((n) => { const on = n.dataset.actor === id; n.classList.toggle('selected', on); n.setAttribute('aria-pressed', on); });
  $$('.arch-edge', svg).forEach((l) => l.classList.toggle('hl', l.dataset.a === id || l.dataset.b === id));
}
function selectArchActor(id) {
  const a = ACTORS[id];
  APP.archSel = id;
  markArchSelection();
  const flows = FLOWS.filter((f) => f.actors.includes(id));
  $('#archSide').innerHTML = `<h2>${esc(a.name)}</h2><div class="pill" style="margin-bottom:8px">${esc(a.role)}</div>
    <p>${esc(a.desc)}</p><h3>Key facts</h3><ul class="tight">${a.facts.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
    <h3>Appears in ${flows.length} flow${flows.length === 1 ? '' : 's'}</h3><div style="display:flex;flex-direction:column;gap:6px">${flows.map((f) => `<a class="btn sm" style="justify-content:flex-start" href="#flow/${f.id}">${esc(f.title)}</a>`).join('') || '<span class="soft">Architecture only</span>'}</div>`;
  announce(`${a.name} selected. It appears in ${flows.length} flow${flows.length === 1 ? '' : 's'}. The details are next to the diagram.`);
}
