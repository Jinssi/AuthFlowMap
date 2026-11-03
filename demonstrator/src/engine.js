'use strict';
/* =====================================================================
   ENGINE: step normalisation, HTTP/token rendering, diagram and sequence SVGs.
   ===================================================================== */
const DET = {
  protocol: { short: 'Protocol', label: 'Deterministic protocol step', desc: 'Fixed protocol logic. The same input always gives the same output, and no AI is involved.' },
  ai: { short: 'AI decision', label: 'AI model decision', desc: 'The LLM chose this, so the next run might differ. Identity and access never hang on it. The host, Entra ID and the resource enforce those.' },
  human: { short: 'Human', label: 'Human action', desc: 'A person signs in, approves something or types a code.' },
  policy: { short: 'Entra policy', label: 'Entra policy evaluation', desc: 'Entra ID applies your configuration before it issues anything. That means Conditional Access, consent, app role assignments, cross-tenant access and federated credential rules. At the Global Secure Access edge, Entra also enforces the security profiles Conditional Access links to the user before traffic goes on.' },
  resource: { short: 'Resource policy', label: 'Resource authorization decision', desc: 'The API, MCP server or data service decides with its own rules, after the token is valid. That means scopes and roles, authentication context, permissions on the data, tenant settings and business limits.' },
};
// Components on the identity side. A policy step that involves none of them is the resource deciding, not Entra.
const IDENTITY_SIDE = new Set(['entra', 'homeEntra', 'risk', 'intune']);
// The Global Secure Access edge enforces Entra policy on traffic. It never issues tokens, so its decisions are Authorize, not Issue.
const POLICY_SIDE = new Set([...IDENTITY_SIDE, 'sse']);
const effDet = (s) => (s.det === 'policy' && !POLICY_SIDE.has(s.from) && !POLICY_SIDE.has(s.to) ? 'resource' : s.det || 'protocol');
const STAGES = {
  issue: { short: 'Issue', desc: 'Entra ID, or another identity provider, decides whether to issue a token and what goes in it.' },
  validate: { short: 'Validate', desc: 'The receiver checks the token itself: signature, issuer, audience and lifetime. A valid token proves who is calling, not what they may do.' },
  authorize: { short: 'Authorize', desc: 'The receiver decides whether this caller may do this action now, with the claims, its own rules and the permissions on the data.' },
};
const TOKEN_CHECK = /signature|jwks|\biss\b|issuer|\baud\b|audience|\bexp\b|expir|lifetime|\bnbf\b|\btid\b|\balg\b|\bkid\b|not before|\bnonce\b|token valid/i;
const checkObj = (c) => (typeof c === 'string' ? { name: c, ok: true } : c);
const checkKind = (c) => { const o = checkObj(c); return o.kind || (TOKEN_CHECK.test(o.name || '') ? 'token' : 'access'); };
/** Which of issue, validate and authorize a step belongs to. Explicit `stage` wins; otherwise it follows from who is involved and what was checked. */
function stepStages(s) {
  if (s.stage) return [].concat(s.stage);
  if (IDENTITY_SIDE.has(s.from) || IDENTITY_SIDE.has(s.to)) {
    const decides = s.det === 'policy' || (s.checks || []).length || (IDENTITY_SIDE.has(s.from) && s.res && s.res.status < 400 && /token|code|assertion|saml/i.test(`${s.label} ${s.title}`));
    return decides ? ['issue'] : [];
  }
  const kinds = new Set((s.checks || []).map(checkKind));
  // Policy steps here are the Global Secure Access edge deciding on traffic (effDet keeps 'policy' only for it).
  const decides = s.det === 'resource' || s.det === 'policy';
  // Client-side protocol checks such as state or the passkey origin are neither token validation nor an access decision.
  if (!kinds.has('token') && !decides) return [];
  const out = [];
  if (kinds.has('token')) out.push('validate');
  if (kinds.has('access') || decides) out.push('authorize');
  return out;
}
const NODE_W = 176, NODE_H = 60;
const detPill = (d) => `<span class="pill det det-${d || 'protocol'}" title="${esc(DET[d || 'protocol'].desc)}">${esc(DET[d || 'protocol'].short)}</span>`;
const stagePills = (s) => stepStages(s).map((g) => `<span class="pill stage stage-${g}" title="${esc(STAGES[g].desc)}"><span class="sr-only">Stage: </span>${STAGES[g].short}</span>`).join('');
const trunc = (s, n) => { s = String(s ?? ''); return s.length > n ? `${s.slice(0, n - 1)}…` : s; };
const actorLabel = (id) => (ACTORS[id] ? ACTORS[id].name : id);
const PKCE_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
const reducedMotion = () => window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

/* ---------- accessibility helpers ---------- */
let announceTimer = 0;
/** Speak a short message through the polite live region. Clearing first makes a repeated message speak again. */
function announce(msg) {
  const el = $('#srAnnounce'); if (!el) return;
  el.textContent = ''; clearTimeout(announceTimer);
  announceTimer = setTimeout(() => { el.textContent = msg; }, 60);
}
/** Re-render root with innerHTML without dropping keyboard focus: the matching control in the new markup gets focus back. */
function keepFocus(root, render, fallbackSel) {
  const a = document.activeElement;
  let sel = null;
  if (root && a && a !== root && root.contains(a)) {
    const el = a.closest('[data-tab],[data-k],[data-i],[id]');
    if (el && root.contains(el)) {
      const d = el.dataset;
      if (d.tab) sel = `[data-tab="${CSS.escape(d.tab)}"]`;
      else if (d.k) sel = `[data-k="${CSS.escape(d.k)}"][data-v="${CSS.escape(d.v || '')}"]`;
      else if (d.i) sel = `[data-i="${CSS.escape(d.i)}"]`;
      else if (el.id) sel = `#${CSS.escape(el.id)}`;
    }
  }
  render();
  if (!sel) return;
  let n = root.querySelector(sel);
  if ((!n || n.disabled) && fallbackSel) n = root.querySelector(fallbackSel);
  n?.focus({ preventScroll: true });
}
/** Size an SVG label pill to its rendered text. Character-count estimates overflow with the monospace font. */
function fitLabel(rect, text, pad = 8) {
  const w = Math.ceil(text.getComputedTextLength()) + pad * 2;
  rect.setAttribute('width', w);
  return w;
}
/** Trim an SVG text or tspan with an ellipsis until it fits max user units. */
function fitText(el, max) {
  if (!(el.getComputedTextLength() > max)) return;
  const full = el.textContent;
  let lo = 0, hi = full.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    el.textContent = `${full.slice(0, mid).trimEnd()}…`;
    if (el.getComputedTextLength() <= max) lo = mid; else hi = mid - 1;
  }
  // Keep whole words, so the visible text stays a run of words from the accessible name (label in name).
  const sp = full.lastIndexOf(' ', lo);
  if (sp > 0 && /\S/.test(full[lo] || '')) lo = sp;
  el.textContent = `${full.slice(0, lo).replace(/[\s·,+/:;-]+$/, '')}…`;
}
const NODE_TEXT_W = 124;
/** Wrap long component names onto two lines and trim everything marked data-max, by measuring the rendered text. */
function fitSvgText(root) {
  $$('.node text.name', root).forEach((name) => {
    if (!(name.getComputedTextLength() > NODE_TEXT_W)) return;
    const words = name.textContent.split(' ');
    if (words.length < 2) { fitText(name, NODE_TEXT_W); return; }
    let k = words.length - 1;
    for (; k > 1; k--) { name.textContent = words.slice(0, k).join(' '); if (name.getComputedTextLength() <= NODE_TEXT_W) break; }
    name.textContent = '';
    [[`${words.slice(0, k).join(' ')} `, 20], [words.slice(k).join(' '), 36]].forEach(([txt, y]) => {
      const t = document.createElementNS('http://www.w3.org/2000/svg', 'tspan');
      t.setAttribute('x', 44); t.setAttribute('y', y); t.textContent = txt;
      name.append(t); fitText(t, NODE_TEXT_W);
    });
    name.closest('.node').querySelector('text.role')?.setAttribute('y', 51);
  });
  $$('[data-max]', root).forEach((el) => fitText(el, Number(el.dataset.max)));
}

/* ---------- diagram zoom and pan ---------- */
const ZOOM_MIN = 0.4, ZOOM_MAX = 2.5;
let zoomPrefs = {};
try { zoomPrefs = JSON.parse(localStorage.getItem('authflow-zoom')) || {}; } catch { /* storage blocked */ }
const zoomBarHtml = () => `<div class="zoom-bar" role="group" aria-label="Diagram zoom">
  <button type="button" class="zb" data-z="out" aria-label="Zoom out" title="Zoom out, key −" aria-keyshortcuts="-">−</button>
  <span class="zb-val" aria-hidden="true">100%</span>
  <button type="button" class="zb" data-z="in" aria-label="Zoom in" title="Zoom in, key +" aria-keyshortcuts="+">+</button>
  <button type="button" class="zb" data-z="fit" aria-pressed="true" title="Fit the space, but never smaller than readable. Key 0" aria-keyshortcuts="0">Fit</button>
  <button type="button" class="zb" data-z="one" aria-pressed="false" title="Actual size, one diagram unit per pixel">100%</button></div>`;
/**
 * Pan and zoom for the SVGs marked .zsvg inside a scroll viewport. Scale 1 is one SVG unit per CSS pixel.
 * Fit fills the viewport but never shrinks the diagram's body text below 12 CSS px (16 px when presenting);
 * past that the viewport scrolls instead. A manual zoom level is remembered per diagram kind.
 */
class ZoomView {
  constructor(vp, bar, opts) {
    this.vp = vp; this.bar = bar; this.scale = 1;
    Object.assign(this, { key: 'diagram', font: 14, fitHeight: true }, opts);
    vp.classList.add('zoom-vp');
    bar?.addEventListener('click', (e) => {
      const z = e.target.closest('[data-z]')?.dataset.z;
      if (z === 'in') this.zoomBy(1.25); else if (z === 'out') this.zoomBy(0.8); else if (z === 'fit') this.set('fit'); else if (z === 'one') this.set(1);
    });
    vp.addEventListener('wheel', (e) => { if (!e.ctrlKey) return; e.preventDefault(); this.zoomBy(Math.exp(-e.deltaY * 0.0025), e); }, { passive: false });
    // A mouse click on the background shouldn't move focus here, so the arrow keys keep stepping the flow.
    vp.addEventListener('mousedown', (e) => { if (e.target === vp || !e.target.closest('[tabindex], a, button')) e.preventDefault(); });
    let drag = null;
    vp.addEventListener('pointerdown', (e) => {
      if (e.button !== 0 || e.pointerType === 'touch' || !vp.classList.contains('pannable')) return;
      drag = { x: e.clientX, y: e.clientY, l: vp.scrollLeft, t: vp.scrollTop, id: e.pointerId, moved: false };
    });
    vp.addEventListener('pointermove', (e) => {
      if (!drag || e.pointerId !== drag.id) return;
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (!drag.moved) { if (Math.hypot(dx, dy) < 5) return; drag.moved = true; vp.setPointerCapture(e.pointerId); vp.classList.add('panning'); }
      vp.scrollLeft = drag.l - dx; vp.scrollTop = drag.t - dy;
    });
    const end = () => {
      if (drag?.moved) { vp.classList.remove('panning'); this.eatClick = true; setTimeout(() => { this.eatClick = false; }, 0); }
      drag = null;
    };
    vp.addEventListener('pointerup', end); vp.addEventListener('pointercancel', end);
    vp.addEventListener('click', (e) => { if (this.eatClick) { this.eatClick = false; e.stopImmediatePropagation(); e.preventDefault(); } }, true);
    if (window.ResizeObserver) { this.ro = new ResizeObserver(() => { if (this.pref() === 'fit') this.apply(); }); this.ro.observe(vp); }
  }
  destroy() { this.ro?.disconnect(); }
  pref() { return zoomPrefs[this.key] ?? 'fit'; }
  configure(opts) { Object.assign(this, opts); this.apply(); }
  readable() { return (document.body.classList.contains('presenter') ? 16 : 12) / this.font; }
  fitScale() {
    const svgs = $$('svg.zsvg', this.vp);
    let w = 0, h = 0;
    svgs.forEach((s) => { const vb = s.viewBox.baseVal; w = Math.max(w, vb.width); h += vb.height; });
    if (!w) return 1;
    const cs = getComputedStyle(this.vp);
    let s = (this.vp.clientWidth - parseFloat(cs.paddingLeft) - parseFloat(cs.paddingRight)) / w;
    const mh = parseFloat(cs.maxHeight);
    if (this.fitHeight && mh > 0) s = Math.min(s, (mh - parseFloat(cs.paddingTop) - parseFloat(cs.paddingBottom) - 2) / h);
    return Math.min(1.6, Math.max(this.readable(), s));
  }
  apply(anchor) {
    const vp = this.vp, pref = this.pref(), s0 = this.scale;
    const s = pref === 'fit' ? this.fitScale() : Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, Number(pref) || 1));
    const r = vp.getBoundingClientRect();
    const px = anchor ? anchor.clientX - r.left : vp.clientWidth / 2, py = anchor ? anchor.clientY - r.top : vp.clientHeight / 2;
    const cx = (vp.scrollLeft + px) / s0, cy = (vp.scrollTop + py) / s0;
    $$('svg.zsvg', vp).forEach((svg) => { const vb = svg.viewBox.baseVal; svg.style.width = `${vb.width * s}px`; svg.style.height = `${vb.height * s}px`; });
    this.scale = s;
    if (s !== s0) { vp.scrollLeft = cx * s - px; vp.scrollTop = cy * s - py; }
    const pannable = vp.scrollWidth > vp.clientWidth + 1 || vp.scrollHeight > vp.clientHeight + 1;
    vp.classList.toggle('pannable', pannable);
    if (pannable) vp.tabIndex = 0; else vp.removeAttribute('tabindex');
    if (this.bar) {
      this.bar.querySelector('.zb-val').textContent = `${Math.round(s * 100)}%`;
      this.bar.querySelector('[data-z=fit]').setAttribute('aria-pressed', pref === 'fit');
      this.bar.querySelector('[data-z=one]').setAttribute('aria-pressed', pref !== 'fit' && Math.abs(s - 1) < 0.001);
      this.bar.querySelector('[data-z=out]').disabled = s <= ZOOM_MIN + 0.001;
      this.bar.querySelector('[data-z=in]').disabled = s >= ZOOM_MAX - 0.001;
    }
  }
  set(pref, anchor) {
    zoomPrefs[this.key] = pref;
    try { localStorage.setItem('authflow-zoom', JSON.stringify(zoomPrefs)); } catch { /* storage blocked */ }
    this.apply(anchor);
    if (!anchor) announce(`Diagram zoom ${pref === 'fit' ? 'fit, ' : ''}${Math.round(this.scale * 100)} percent`);
  }
  zoomBy(f, anchor) {
    const s = Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, this.scale * f));
    this.set(anchor ? s : Math.round(s * 20) / 20, anchor);
  }
}

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
  return { ...st, det: effDet(st), tokens, checks: st.checks || [], src: 'sim', status };
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
  const out = {
    id: ev.stepId, from: ev.from || t.from, to: ev.to || t.to, label: ev.label || t.label, title: t.title || ev.label || ev.stepId,
    det: t.det === 'resource' ? 'resource' : (ev.determinism || t.det || 'protocol'), stage: t.stage, desc: t.desc || '', why: t.why, kv: ev.data || null, note: ev.note,
    req: convReq(ev.request), res: convRes(ev.response), tokens: ev.tokens || [], checks: ev.checks || [],
    status: ev.status || 'ok', src: ev.simulated ? 'sim' : 'live', ts: ev.ts,
  };
  out.det = effDet(out);
  return out;
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
  return `<tr class="${info && info.key ? 'key' : ''}"><td class="k">${esc(k).replace(/_/g, '_<wbr>')}</td><td class="v">${esc(val)}</td><td class="d">${esc(d)}</td></tr>`;
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
/** Checks in two groups: is the token genuine and meant for me, and is this caller allowed to do this. Identity-side steps keep one list. */
function renderChecks(checks, step) {
  if (!checks || !checks.length) return '<div class="insp-empty">No checks in this step.</div>';
  const li = (c) => {
    const o = checkObj(c);
    const mark = o.ok === true ? '<span class="ok">✓</span>' : o.ok === false ? '<span class="bad">✗</span>' : '<span class="na">?</span>';
    return `<li>${mark}<div>${esc(o.name)}${o.detail ? `<div class="soft" style="font-size:12px">${esc(o.detail)}</div>` : ''}</div></li>`;
  };
  if (step && stepStages(step).includes('issue')) return `<h3 class="checks-h">Checked before anything is issued</h3><ul class="checks">${checks.map(li).join('')}</ul>`;
  if (!step || !stepStages(step).includes('validate') || !stepStages(step).includes('authorize')) return `<ul class="checks">${checks.map(li).join('')}</ul>`;
  const groups = [
    ['token', 'Token valid?', 'Proves the token is genuine, current and meant for this receiver. It says nothing about what the caller may do.'],
    ['access', 'Allowed to do this?', 'The receiver\'s own decision about this caller, this action and this data.'],
  ];
  return groups.map(([k, h, d]) => {
    const list = checks.filter((c) => checkKind(c) === k);
    if (!list.length) return '';
    const failed = list.some((c) => checkObj(c).ok === false);
    return `<h3 class="checks-h">${h} <span class="checks-verdict ${failed ? 'bad' : 'ok'}">${failed ? 'No' : 'Yes'}</span></h3><p class="soft checks-d">${d}</p><ul class="checks">${list.map(li).join('')}</ul>`;
  }).join('');
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
  const label = `${esc(a.name)}, ${esc(a.role)}`;
  return `<g class="node ${extraCls} ${id === 'entra' ? 'entra' : ''}" data-actor="${id}" transform="translate(${x - NODE_W / 2},${y - NODE_H / 2})" tabindex="0" role="button" aria-label="${label}" data-label="${label}">
    <rect class="box" rx="10" width="${NODE_W}" height="${NODE_H}"/>
    <text class="role-tag s" x="${NODE_W / 2}" y="-7" text-anchor="middle" aria-hidden="true">▲ SENDING</text>
    <text class="role-tag r" x="${NODE_W / 2}" y="-7" text-anchor="middle" aria-hidden="true">▼ RECEIVING</text>
    <text class="role-tag w" x="${NODE_W / 2}" y="-7" text-anchor="middle" aria-hidden="true">⚙ PROCESSING</text>
    <text class="ico" x="12" y="37" aria-hidden="true">${a.icon}</text>
    <text class="name" x="44" y="26">${esc(a.name)}</text>
    <text class="role" x="44" y="43" data-max="${NODE_TEXT_W}">${esc(a.role)}</text></g>`;
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
  return `<svg class="zsvg stage-svg" viewBox="${x0} ${y0} ${Math.max(x1 - x0, 600)} ${Math.max(y1 - y0, 300)}" role="group" aria-label="Component diagram, ${Object.keys(pos).length} components. Tab to a component and press Enter for its description. The step list has every hop as text.">${SVG_DEFS}<g class="edges" aria-hidden="true">${edges}</g><g class="nodes">${nodes}</g>
    <g id="edgeLbl" style="display:none" aria-hidden="true"><rect class="edge-label-bg" rx="6" height="20"/><text class="edge-label active" y="14"></text></g><g id="packet" class="packet" style="display:none" aria-hidden="true"></g></svg>`;
}

/* ---------- sequence diagram ---------- */
const SEQ_HEAD_H = 54;
/** Two SVGs in one coordinate system: the actor header, which stays visible with position: sticky, and the message rows. */
function buildSequence(flow, steps) {
  const actors = [...flow.actors];
  steps.forEach((s) => [s.from, s.to].forEach((a) => { if (a && !actors.includes(a)) actors.push(a); }));
  const n = actors.length, W = Math.max(1000, n * 160), left = 56, right = 10, colW = (W - left - right) / n;
  const x = (id) => left + colW * (actors.indexOf(id) + 0.5);
  const y0 = 66, rowH = 46, H = y0 + steps.length * rowH + 16;
  let head = `<svg class="zsvg" viewBox="0 0 ${W} ${SEQ_HEAD_H}" aria-hidden="true">`;
  let s = `<svg class="zsvg stage-svg" viewBox="0 ${SEQ_HEAD_H} ${W} ${H - SEQ_HEAD_H}" role="img" aria-label="Sequence diagram with ${steps.length} messages between ${actors.length} components. The step list has the same messages as text.">${SVG_DEFS}`;
  actors.forEach((a) => {
    const A = ACTORS[a] || { icon: '', name: a };
    head += `<g class="seq-head"><title>${esc(A.name)}</title><rect x="${x(a) - colW / 2 + 5}" y="6" width="${colW - 10}" height="44" rx="8"/><text x="${x(a)}" y="25" text-anchor="middle">${A.icon}</text><text x="${x(a)}" y="42" text-anchor="middle" data-max="${colW - 18}">${esc(A.name)}</text></g>`;
    head += `<line class="lifeline" x1="${x(a)}" y1="50" x2="${x(a)}" y2="${SEQ_HEAD_H}"/>`;
    s += `<line class="lifeline" x1="${x(a)}" y1="${SEQ_HEAD_H}" x2="${x(a)}" y2="${H - 6}"/>`;
  });
  steps.forEach((st, i) => {
    const yTop = y0 + i * rowH, y = yTop + rowH / 2 + 7;
    s += `<rect class="seq-row-bg" data-i="${i}" x="0" y="${yTop}" width="${W}" height="${rowH}"/>`;
    s += `<text class="seq-num" x="8" y="${y + 4}">${i + 1}</text><circle class="seq-det ${st.det}" cx="34" cy="${y}" r="5"><title>${esc(DET[st.det]?.label || '')}</title></circle>`;
    if (st.from === st.to) {
      const X = x(st.from);
      s += `<path class="seq-arrow future" id="sa-${i}" d="M${X},${y - 9} h34 v16 h-30" marker-end="url(#ah)"/>`;
      s += `<g><title>${esc(st.label)}</title><text class="seq-label future" id="sl-${i}" x="${X + 40}" y="${y + 3}" data-max="${Math.min(W - X - 48, colW * 1.8)}">${esc(st.label)}</text></g>`;
    } else {
      const x1 = x(st.from), x2 = x(st.to), dir = x2 > x1 ? 1 : -1, mid = (x1 + x2) / 2;
      const max = Math.min(2 * Math.min(mid - 48, W - 8 - mid), Math.max(Math.abs(x2 - x1) - 16, 280));
      s += `<path class="seq-arrow future" id="sa-${i}" d="M${x1},${y} L${x2 - dir * 4},${y}" marker-end="url(#ah)"/>`;
      s += `<g><title>${esc(st.label)}</title><text class="seq-label future" id="sl-${i}" x="${mid}" y="${y - 6}" text-anchor="middle" data-max="${max}">${esc(st.label)}</text></g>`;
    }
  });
  s += '<g id="packet" class="packet" style="display:none"></g></svg>';
  return `<div class="seq-sticky">${head}</svg></div>${s}`;
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
  g.innerHTML = `<circle class="halo" r="15"/><circle r="7"/><g transform="translate(12,-24)"><rect rx="9" height="18"/><text x="7" y="13">${esc(label)}</text></g>`;
  g.style.display = '';
  fitLabel(g.querySelector('rect'), g.querySelector('text'), 7);
  const L = pathEl.getTotalLength();
  if (reducedMotion()) {
    const p = pathEl.getPointAtLength(L);
    g.setAttribute('transform', `translate(${p.x},${p.y})`);
    const t = setTimeout(onDone, Math.min(dur, 400));
    return () => clearTimeout(t);
  }
  const t0 = performance.now();
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
