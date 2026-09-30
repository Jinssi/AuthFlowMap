'use strict';
/* =====================================================================
   ENGINE: step normalisation, HTTP/token rendering, diagram and sequence SVGs.
   ===================================================================== */
const DET = {
  protocol: { short: 'Protocol', label: 'Deterministic protocol step', desc: 'Fixed protocol logic. The same input always gives the same output, and no AI is involved.' },
  ai: { short: 'AI decision', label: 'AI model decision', desc: 'The LLM chose this, so the next run might differ. Identity and access never hang on it. The host, Entra ID and the resource enforce those.' },
  human: { short: 'Human', label: 'Human action', desc: 'A person signs in, approves something or types a code.' },
  policy: { short: 'Policy', label: 'Policy evaluation', desc: 'Entra ID applies your configuration. That means Conditional Access, consent, app role assignments and federated credential rules.' },
};
const NODE_W = 176, NODE_H = 60;
const detPill = (d) => `<span class="pill det det-${d || 'protocol'}" title="${esc(DET[d || 'protocol'].desc)}">${esc(DET[d || 'protocol'].short)}</span>`;
const trunc = (s, n) => { s = String(s ?? ''); return s.length > n ? `${s.slice(0, n - 1)}…` : s; };
const actorLabel = (id) => (ACTORS[id] ? ACTORS[id].name : id);
const PKCE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

function bytesToB64url(bytes) {
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function sha256b64url(s) {
  if (!crypto.subtle) return randStr(43);
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
  return bytesToB64url(new Uint8Array(d));
}

/* ---------- simulated run context ---------- */
async function makeSimCtx(flow, variant) {
  const t = nowSec();
  const verifier = randStr(64, PKCE_ALPHABET);
  const vars = {
    verifier, challenge: await sha256b64url(verifier), state: randStr(22), nonce: uuid(),
    code: `1.AR8A${randStr(110)}`, rt: `1.AR8A${randStr(90)}`, sid: uuid(), jti: uuid(),
    userCode: randStr(9, 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'), deviceCode: `DAQABIQEAAAD${randStr(60)}`,
  };
  const ctx = { t, vars, variant, raw: {}, tok: {}, rawToName: {} };
  const toks = flow.tokens ? flow.tokens(ctx) : {};
  for (const [name, def] of Object.entries(toks)) {
    const raw = fakeJwt(def.header, def.payload);
    ctx.raw[name] = raw; ctx.tok[name] = def; ctx.rawToName[raw] = name;
  }
  return ctx;
}
function templateSteps(flow, variant) {
  return flow.steps({ t: nowSec(), vars: {}, raw: {}, tok: {}, rawToName: {}, variant });
}
function subst(v, ctx) {
  if (typeof v === 'string') return v.replace(/\{\{(\w+)\}\}/g, (m, k) => ctx.raw[k] ?? ctx.vars[k] ?? m);
  if (Array.isArray(v)) return v.map((x) => subst(x, ctx));
  if (v && typeof v === 'object') { const o = {}; for (const [k, x] of Object.entries(v)) o[k] = subst(x, ctx); return o; }
  return v;
}
function scanTokens(obj, add, key = '') {
  if (typeof obj === 'string') {
    if (/^authorization$/i.test(key) && obj.startsWith('Bearer ')) add(obj.slice(7), 'Authorization: Bearer');
    else if (isJwt(obj)) add(obj, key);
    return;
  }
  if (Array.isArray(obj)) obj.forEach((x) => scanTokens(x, add, key));
  else if (obj && typeof obj === 'object') Object.entries(obj).forEach(([k, v]) => scanTokens(v, add, k));
}
function normSimStep(s, ctx) {
  const st = subst(s, ctx);
  const tokens = []; const seen = new Set();
  const add = (raw, field) => {
    if (!isJwt(raw) || seen.has(raw)) return;
    seen.add(raw);
    const name = ctx.rawToName[raw]; const dec = decodeJwt(raw);
    tokens.push({ name, label: name ? ctx.tok[name].label : field, field, masked: maskToken(raw), header: dec?.header, payload: dec?.payload });
  };
  (s.tok || []).forEach((n) => ctx.raw[n] && add(ctx.raw[n], n));
  if (st.req) scanTokens(st.req, add);
  if (st.res) scanTokens(st.res, add);
  const status = st.status || (st.res && st.res.status >= 400 ? 'error' : 'ok');
  return { ...st, tokens, checks: st.checks || [], src: 'sim', status };
}
/** Convert a live trace event (server or browser) into the display model, enriched by the flow template. */
function normLiveEvent(ev, tpl) {
  const t = tpl || {};
  const convReq = (r) => {
    if (!r) return null;
    const ct = Object.entries(r.headers || {}).find(([k]) => k.toLowerCase() === 'content-type')?.[1] || '';
    const out = { method: r.method, url: r.url, headers: r.headers || {} };
    if (r.body && typeof r.body === 'object') out[/x-www-form/.test(ct) ? 'form' : 'json'] = r.body;
    else if (r.body) out.text = String(r.body);
    return out;
  };
  const convRes = (r) => {
    if (!r) return null;
    const out = { status: r.status, statusText: r.statusText || '', headers: r.headers || {} };
    if (r.body && typeof r.body === 'object') out.json = r.body; else if (r.body) out.text = String(r.body);
    return out;
  };
  return {
    id: ev.stepId, from: ev.from || t.from, to: ev.to || t.to, label: ev.label || t.label, title: t.title || ev.label || ev.stepId,
    det: ev.determinism || t.det || 'protocol', desc: t.desc || '', why: t.why, kv: ev.data || null, note: ev.note,
    req: convReq(ev.request), res: convRes(ev.response), tokens: ev.tokens || [], checks: ev.checks || [],
    status: ev.status || 'ok', src: ev.simulated ? 'sim' : 'live', ts: ev.ts,
  };
}

/* ---------- display masking & HTTP rendering ---------- */
function dispVal(k, v) {
  if (v == null) return '';
  if (typeof v !== 'string') return JSON.stringify(v);
  if (/^client_secret$/i.test(k)) return v.includes('redacted') ? v : '••••••••[redacted]';
  if (/^authorization$/i.test(k) && v.startsWith('Bearer ') && isJwt(v.slice(7))) return `Bearer ${maskToken(v.slice(7))}`;
  if (isJwt(v)) return maskToken(v);
  return v;
}
function maskDeep(o, k = '') {
  if (typeof o === 'string') return dispVal(k, o);
  if (Array.isArray(o)) return o.map((x) => maskDeep(x, k));
  if (o && typeof o === 'object') { const r = {}; for (const [kk, v] of Object.entries(o)) r[kk] = maskDeep(v, kk); return r; }
  return o;
}
function jsonHtml(obj) {
  const s = JSON.stringify(maskDeep(obj), null, 2) ?? '';
  return esc(s).replace(/(&quot;[^&]*?&quot;)(\s*:)/g, '<span class="k">$1</span>$2');
}
function renderRequest(req) {
  if (!req) return '<div class="insp-empty">No HTTP request in this step.</div>';
  let u = null;
  try { u = new URL(req.url); } catch { /* relative or non-URL */ }
  const query = req.query || (u && u.search ? Object.fromEntries(u.searchParams) : null);
  const path = u ? u.pathname : req.url;
  let out = `<span class="m">${esc(req.method || 'GET')}</span> ${esc(path)}`;
  if (query) out += `?\n${Object.entries(query).map(([k, v], i) => `    ${i ? '&amp;' : ' '}<span class="k">${esc(k)}</span>=${esc(dispVal(k, v))}`).join('\n')}`;
  out += ' HTTP/1.1\n';
  if (u) out += `<span class="h">Host</span>: ${esc(u.host)}\n`;
  for (const [k, v] of Object.entries(req.headers || {})) out += `<span class="h">${esc(k)}</span>: ${esc(dispVal(k, v))}\n`;
  if (req.form) out += `\n${Object.entries(req.form).map(([k, v], i) => `${i ? '&amp;' : ''}<span class="k">${esc(k)}</span>=${esc(dispVal(k, v))}`).join('\n')}`;
  else if (req.json) out += `\n${jsonHtml(req.json)}`;
  else if (req.text) out += `\n${esc(req.text)}`;
  return `<pre class="http">${out}</pre>`;
}
function renderResponse(res) {
  if (!res) return '<div class="insp-empty">No HTTP response in this step.</div>';
  const cls = res.status < 400 ? 'st-ok' : 'st-bad';
  let out = `HTTP/1.1 <span class="${cls}">${esc(res.status)} ${esc(res.statusText || '')}</span>\n`;
  for (const [k, v] of Object.entries(res.headers || {})) out += `<span class="h">${esc(k)}</span>: ${esc(dispVal(k, v))}\n`;
  if (res.json !== undefined) out += `\n${jsonHtml(res.json)}`;
  else if (res.form) out += `\n${Object.entries(res.form).map(([k, v]) => `<span class="k">${esc(k)}</span>=${esc(dispVal(k, v))}`).join('\n&amp;')}`;
  else if (res.text) out += `\n${esc(res.text)}`;
  return `<pre class="http">${out}</pre>`;
}
function claimRow(k, v) {
  const info = CLAIM_INFO[k];
  const d = typeof info === 'string' ? info : info?.d || '';
  let val = Array.isArray(v) ? v.join(' ') : typeof v === 'object' ? JSON.stringify(v) : String(v);
  if (['iat', 'nbf', 'exp'].includes(k) && typeof v === 'number') val += `  (${new Date(v * 1000).toLocaleString()})`;
  return `<tr class="${info && info.key ? 'key' : ''}"><td class="k">${esc(k)}</td><td class="v">${esc(val)}</td><td class="d">${esc(d)}</td></tr>`;
}
function renderTokens(tokens) {
  if (!tokens || !tokens.length) return '<div class="insp-empty">No token in this step.</div>';
  return tokens.map((t) => {
    const [a = '', b = '', c = ''] = String(t.masked || '').split('.');
    const hdr = t.header ? Object.entries(t.header).map(([k, v]) => claimRow(k, v)).join('') : '';
    const pl = t.payload ? Object.entries(t.payload).filter(([, v]) => v !== undefined).map(([k, v]) => claimRow(k, v)).join('') : '<tr><td colspan="3">Not a JWT</td></tr>';
    return `<div class="token-card"><div class="tc-head"><span>${esc(t.label || t.field || 'token')}</span>${t.field && t.field !== t.name ? `<span class="pill">${esc(t.field)}</span>` : ''}</div>
      <div class="token-raw" title="Masked. The signature is never shown"><span class="p1">${esc(a)}</span>.<span class="p2">${esc(b)}</span>.<span class="p3">${esc(c)}</span></div>
      <table class="claims"><tbody>${pl}<tr><td colspan="3" class="d" style="background:var(--cp-surface-soft)">Header</td></tr>${hdr}</tbody></table></div>`;
  }).join('');
}
function renderChecks(checks) {
  if (!checks || !checks.length) return '<div class="insp-empty">No checks in this step.</div>';
  return `<ul class="checks">${checks.map((c) => {
    const o = typeof c === 'string' ? { name: c, ok: true } : c;
    const mark = o.ok === true ? '<span class="ok">✓</span>' : o.ok === false ? '<span class="bad">✗</span>' : '<span class="na">?</span>';
    return `<li>${mark}<div>${esc(o.name)}${o.detail ? `<div class="soft" style="font-size:12px">${esc(o.detail)}</div>` : ''}</div></li>`;
  }).join('')}</ul>`;
}

/* ---------- geometry ---------- */
function rectEdge(cx, cy, dx, dy, pad = 5) {
  const hw = NODE_W / 2 + pad, hh = NODE_H / 2 + pad;
  const t = Math.min(hw / Math.max(Math.abs(dx), 1e-6), hh / Math.max(Math.abs(dy), 1e-6));
  return [cx + dx * t, cy + dy * t];
}
function edgeGeom(p1, p2) {
  const [x1, y1] = p1, [x2, y2] = p2;
  const dx = x2 - x1, dy = y2 - y1, len = Math.hypot(dx, dy) || 1, off = 28;
  const mx = (x1 + x2) / 2 - (dy / len) * off, my = (y1 + y2) / 2 + (dx / len) * off;
  const a = rectEdge(x1, y1, mx - x1, my - y1), b = rectEdge(x2, y2, mx - x2, my - y2, 9);
  return { d: `M${a[0].toFixed(1)},${a[1].toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${b[0].toFixed(1)},${b[1].toFixed(1)}`, mid: [(a[0] + 2 * mx + b[0]) / 4, (a[1] + 2 * my + b[1]) / 4] };
}
function nodeSvg(id, x, y, extraCls = '') {
  const a = ACTORS[id] || { icon: '▫️', name: id, role: '' };
  return `<g class="node ${extraCls} ${id === 'entra' ? 'entra' : ''}" data-actor="${id}" transform="translate(${x - NODE_W / 2},${y - NODE_H / 2})">
    <rect class="box" rx="10" width="${NODE_W}" height="${NODE_H}"/>
    <text class="ico" x="12" y="37">${a.icon}</text>
    <text class="name" x="44" y="26">${esc(trunc(a.name, 19))}</text>
    <text class="role" x="44" y="43">${esc(trunc(a.role, 27))}</text>
    <text class="role-tag s" x="${NODE_W / 2}" y="-7" text-anchor="middle">▲ SENDING</text>
    <text class="role-tag r" x="${NODE_W / 2}" y="-7" text-anchor="middle">▼ RECEIVING</text>
    <text class="role-tag w" x="${NODE_W / 2}" y="-7" text-anchor="middle">⚙ PROCESSING</text>
    <title>${esc(a.name)}: ${esc(a.role)}</title></g>`;
}
const SVG_DEFS = `<defs>
  <marker id="ah" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="arrowhead" d="M0,0 L10,5 L0,10 z"/></marker>
  <marker id="ah-a" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path class="arrowhead active" d="M0,0 L10,5 L0,10 z"/></marker>
</defs>`;

/* ---------- component diagram for a flow ---------- */
function buildDiagram(flow, steps) {
  const pos = { ...flow.layout };
  steps.forEach((s) => [s.from, s.to].forEach((a) => { if (a && !pos[a]) pos[a] = [500, 440]; }));
  const pairs = [];
  steps.forEach((s) => { if (s.from !== s.to && !pairs.some((p) => p.from === s.from && p.to === s.to)) pairs.push({ from: s.from, to: s.to }); });
  const used = new Set(steps.flatMap((s) => [s.from, s.to]));
  const edges = pairs.map((p) => {
    const g = edgeGeom(pos[p.from], pos[p.to]);
    return `<path class="edge used" id="e-${p.from}-${p.to}" d="${g.d}" marker-end="url(#ah)" data-mid="${g.mid.join(',')}"/>`;
  }).join('');
  const nodes = Object.keys(pos).map((id) => nodeSvg(id, pos[id][0], pos[id][1], used.has(id) || !steps.length ? '' : 'dim')).join('');
  const xs = Object.values(pos).map((p) => p[0]), ys = Object.values(pos).map((p) => p[1]);
  const x0 = Math.min(...xs) - NODE_W / 2 - 40, x1 = Math.max(...xs) + NODE_W / 2 + 40;
  const y0 = Math.min(...ys) - NODE_H / 2 - 34, y1 = Math.max(...ys) + NODE_H / 2 + 46;
  return `<svg viewBox="${x0} ${y0} ${Math.max(x1 - x0, 600)} ${Math.max(y1 - y0, 300)}" role="img" aria-label="Component diagram">${SVG_DEFS}<g class="edges">${edges}</g><g class="nodes">${nodes}</g>
    <g id="edgeLbl" style="display:none"><rect class="edge-label-bg" rx="6" height="20"/><text class="edge-label active" y="14"></text></g><g id="packet" class="packet" style="display:none"></g></svg>`;
}

/* ---------- sequence diagram ---------- */
function buildSequence(flow, steps) {
  const actors = [...flow.actors];
  steps.forEach((s) => [s.from, s.to].forEach((a) => { if (a && !actors.includes(a)) actors.push(a); }));
  const W = 1000, left = 56, right = 10, n = actors.length, colW = (W - left - right) / n;
  const x = (id) => left + colW * (actors.indexOf(id) + 0.5);
  const y0 = 66, rowH = 46, H = y0 + steps.length * rowH + 16;
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Sequence diagram">${SVG_DEFS}`;
  actors.forEach((a) => {
    const A = ACTORS[a] || { icon: '', name: a };
    s += `<g class="seq-head"><rect x="${x(a) - colW / 2 + 5}" y="6" width="${colW - 10}" height="44" rx="8"/><text x="${x(a)}" y="25" text-anchor="middle">${A.icon}</text><text x="${x(a)}" y="42" text-anchor="middle">${esc(trunc(A.name, Math.floor(colW / 7.2)))}</text></g>`;
    s += `<line class="lifeline" x1="${x(a)}" y1="50" x2="${x(a)}" y2="${H - 6}"/>`;
  });
  steps.forEach((st, i) => {
    const yTop = y0 + i * rowH, y = yTop + rowH / 2 + 7;
    s += `<rect class="seq-row-bg" data-i="${i}" x="0" y="${yTop}" width="${W}" height="${rowH}"/>`;
    s += `<text class="seq-num" x="8" y="${y + 4}">${i + 1}</text><circle class="seq-det ${st.det}" cx="34" cy="${y}" r="5"><title>${esc(DET[st.det]?.label || '')}</title></circle>`;
    if (st.from === st.to) {
      const X = x(st.from);
      s += `<path class="seq-arrow future" id="sa-${i}" d="M${X},${y - 9} h34 v16 h-30" marker-end="url(#ah)"/>`;
      s += `<text class="seq-label future" id="sl-${i}" x="${X + 40}" y="${y + 3}">${esc(trunc(st.label, 40))}</text>`;
    } else {
      const x1 = x(st.from), x2 = x(st.to), dir = x2 > x1 ? 1 : -1;
      s += `<path class="seq-arrow future" id="sa-${i}" d="M${x1},${y} L${x2 - dir * 4},${y}" marker-end="url(#ah)"/>`;
      s += `<text class="seq-label future" id="sl-${i}" x="${(x1 + x2) / 2}" y="${y - 6}" text-anchor="middle">${esc(trunc(st.label, Math.max(18, Math.floor(Math.abs(x2 - x1) / 7.4))))}</text>`;
    }
  });
  s += '<g id="packet" class="packet" style="display:none"></g></svg>';
  return s;
}

/* ---------- packet animation ---------- */
function packetLabel(step) {
  if (step.tokens && step.tokens.length) return trunc(step.tokens[0].name || step.tokens[0].field || 'token', 16);
  if (step.req) return step.req.method || 'request';
  if (step.res) return String(step.res.status);
  return '●';
}
function animatePacket(svg, pathEl, label, dur, onDone) {
  const g = svg.querySelector('#packet');
  if (!g || !pathEl || typeof pathEl.getTotalLength !== 'function') { onDone(); return () => {}; }
  const w = Math.max(28, label.length * 6.6 + 14);
  g.innerHTML = `<circle class="halo" r="15"/><circle r="7"/><g transform="translate(12,-24)"><rect rx="9" width="${w}" height="18"/><text x="${w / 2}" y="13" text-anchor="middle">${esc(label)}</text></g>`;
  g.style.display = '';
  const L = pathEl.getTotalLength(), t0 = performance.now();
  let raf = 0, stopped = false;
  const ease = (k) => (k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2);
  const frame = (now) => {
    if (stopped) return;
    const k = Math.min(1, (now - t0) / dur), p = pathEl.getPointAtLength(ease(k) * L);
    g.setAttribute('transform', `translate(${p.x},${p.y})`);
    if (k < 1) raf = requestAnimationFrame(frame); else onDone();
  };
  raf = requestAnimationFrame(frame);
  return () => { stopped = true; cancelAnimationFrame(raf); };
}
