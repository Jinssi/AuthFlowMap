'use strict';
/* =====================================================================
   APP SHELL: navigation, routing, architecture page, reference page.
   ===================================================================== */
const APP = { mode: 'sim', speed: 1, view: 'diagram', inspTab: 'overview', player: null, route: '' };
const GROUPS = [
  { id: 'overview', title: 'Start here' },
  { id: 'standard', title: 'Standard OAuth / OIDC' },
  { id: 'access', title: 'Access, MFA and devices' },
  { id: 'agent', title: 'Microsoft Entra Agent ID' },
  { id: 'mcp', title: 'MCP & multi-agent' },
  { id: 'iq', title: 'IQ and grounded agents' },
  { id: 'ref', title: 'Reference' },
];

let toastTimer = 0;
function toast(msg, ms = 3000) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), ms);
}

function renderNav() {
  // One line per row: long names end in an ellipsis, with the full name in the tooltip and the accessible name.
  const item = (href, label) => `<a class="nav-item" href="${href}" title="${esc(label)}"><span>${esc(label)}</span></a>`;
  let html = '';
  for (const g of GROUPS) {
    html += `<div class="nav-group" role="group" aria-labelledby="ng-${g.id}"><div class="nav-group-title" id="ng-${g.id}">${g.title}</div>`;
    if (g.id === 'overview') html += item('#architecture', 'Architecture');
    else if (g.id === 'ref') html += item('#reference', 'Reference tables') + item('#reference/docs', 'Documentation links');
    else FLOWS.filter((f) => f.group === g.id).forEach((f) => { html += item(`#flow/${f.id}`, f.title); });
    html += '</div>';
  }
  $('#nav').innerHTML = html;
}

function route() {
  const h = location.hash || '#architecture';
  // Deep links carry options after the path, as in #flow/obo?variant=x&step=3&view=sequence
  const [path, qs = ''] = h.split('?');
  APP.route = path;
  $$('.nav-item').forEach((b) => { const on = b.getAttribute('href') === path; b.classList.toggle('active', on); if (on) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current'); });
  if (APP.player) { APP.player.destroy(); APP.player = null; Live.cancel(); }
  APP.archZoom?.destroy(); APP.archZoom = null;
  if (isNavDrawer()) setNavOpen(false);
  const main = $('#main'); main.scrollTop = 0; main.onclick = null;
  let title = 'Architecture overview';
  if (path.startsWith('#flow/')) {
    const flow = FLOWS.find((f) => f.id === path.slice(6));
    if (!flow) { main.innerHTML = '<h1>Unknown flow</h1><p><a href="#architecture">Back to the architecture overview</a></p>'; title = 'Unknown flow'; }
    else if (flow.kind === 'simulator') { renderCaSim(main, flow); title = flow.title; }
    else { APP.player = new Player(flow, main, Object.fromEntries(new URLSearchParams(qs))); APP.player.mount(); title = flow.title; }
  } else if (path === '#reference' || path.startsWith('#reference/')) { renderReference(main, path.split('/')[1], new URLSearchParams(qs).get('q')); title = 'Reference tables'; }
  else renderArchitecture(main);
  document.title = `${title} · AuthFlowMap`;
  // After in-app navigation, focus the new content. On first load, leave it at the start so Tab reaches the skip link.
  if (APP.routed) main.focus({ preventScroll: true });
  APP.routed = true;
}

/* ---------- architecture ---------- */
/* The three diagram layouts, the selection and the layout tabs live in arch.js. */
function renderArchitecture(main) {
  APP.archSel = null;
  const flowCard = (f) => `<a class="card card-pad flow-card" href="#flow/${f.id}"><span class="flow-card-head"><b>${esc(f.title)}</b>${f.live ? '<span class="pill live"><span class="sr-only">, </span>LIVE</span>' : ''}</span><span class="muted flow-card-sub">${esc(f.subtitle)}</span></a>`;
  main.innerHTML = `
    <h1>Architecture overview</h1>
    <p class="muted" style="max-width:900px;margin-top:0">Every component that shows up in any of the flows, in three layouts. <b>Click one</b>, or Tab to it and press Enter, to see what it does and which flows use it. Each flow tab opens with a briefing, and <b>Start</b> plays the messages hop by hop.</p>
    <div class="arch-layout">
      <figure class="card arch-svg-wrap" aria-label="Architecture diagram and legend">
        <div class="arch-tools">
          <div class="arch-views" role="tablist" aria-label="Architecture layout">${ARCH_VIEWS.map((v) => `<button role="tab" id="archTab-${v.id}" data-arch-view="${v.id}" aria-controls="archVp">${esc(v.label)}</button>`).join('')}</div>
          <span class="arch-tools-end">${zoomBarHtml()}</span>
        </div>
        <p class="arch-desc soft" id="archDesc"></p>
        <div class="arch-vp" id="archVp" role="tabpanel" aria-describedby="archDesc archPan"><span class="sr-only" id="archPan">When the diagram is larger than the space, drag or use the arrow keys to pan, and Ctrl with the mouse wheel to zoom.</span><svg class="zsvg" id="archSvg" role="group"></svg></div>
        <figcaption class="legend" style="padding:0 8px 6px"><span class="edge-legend">${ARCH_EDGE_KINDS.map((k) => `<span class="edge-key">${edgeSample(k.id)}<span class="soft">${esc(k.label)}</span></span>`).join('')}</span>${Object.keys(DET).map((d) => `${detPill(d)} <span class="soft" style="font-size:12px;margin-right:10px">${esc(DET[d].label)}</span>`).join('')}</figcaption></figure>
      <section class="arch-side card card-pad" id="archSide">
        <h2>Three layers</h2>
        <p><b>Entra ID</b> is the identity layer. It signs in people and workloads, applies policy and <i>issues signed tokens</i>.</p>
        <p><b>Clients and agents</b> <i>ask</i> for tokens. A browser app has no credential. Everything else proves itself with a certificate, a managed identity or a federated credential, then sends the token as a Bearer header.</p>
        <p><b>Resources</b> such as APIs, Graph and MCP servers <i>check</i> each token's signature, audience, expiry and scopes or roles before deciding what data to return.</p>
        <div class="notice info">The AI model sits next to all of this, not inside it. It picks tools. Protocol and policy decide identity and access.</div>
      </section>
    </div>
    <h2 style="margin-top:20px">Flow catalogue</h2>
    ${learnPathHtml()}
    ${['standard', 'access', 'agent', 'mcp', 'iq'].map((g) => `<h3>${GROUPS.find((x) => x.id === g).title}</h3><div class="grid-3">${FLOWS.filter((f) => f.group === g).map(flowCard).join('')}</div>`).join('')}
    <h2 style="margin-top:20px">Token types at a glance</h2>
    <div class="grid-3">
      <div class="card card-pad"><b>Access token</b><p class="muted">Made for a single API, named in <code>aud</code>. Carries <code>scp</code> for delegated access or <code>roles</code> for app access. Lasts about 60 to 90 minutes. Clients shouldn't read it.</p></div>
      <div class="card card-pad"><b>ID token</b><p class="muted">Tells the client who signed in, and only the client reads it. Never send it to an API as a credential.</p></div>
      <div class="card card-pad"><b>Refresh token</b><p class="muted">Opaque and long-lived, and only Entra accepts it. Conditional Access runs again every time it's used. In a SPA it lasts 24 hours.</p></div>
      <div class="card card-pad"><b>Client assertion</b><p class="muted">A JWT the <i>client</i> signs with its certificate, or gets from a managed identity or another IdP. It proves the client's identity at /token.</p></div>
      <div class="card card-pad"><b>Exchange token, T1</b><p class="muted">Agent ID only. Its audience is <code>api://AzureADTokenExchange</code>, and its one use is as the agent identity's credential.</p></div>
      <div class="card card-pad"><b>OBO token</b><p class="muted">Same user, new audience, and the caller becomes the actor. This is how user context crosses API, MCP and agent hops without anyone forwarding a token.</p></div>
    </div>`;
  const svg = $('#archSvg');
  svg.onclick = (e) => { const n = e.target.closest('.node'); if (n) selectArchActor(n.dataset.actor); };
  $$('[data-arch-view]', main).forEach((b) => { b.onclick = () => setArchView(b.dataset.archView, true); });
  APP.archZoom = new ZoomView($('#archVp'), $('.arch-tools .zoom-bar'), { key: 'arch', font: 14, fitHeight: false });
  setArchView(archStoredView(), false);
}

/* ---------- reference ---------- */
function renderReference(main, anchor, q0) {
  const flowTitle = (id) => FLOWS.find((f) => f.id === id)?.title || id;
  main.innerHTML = `<h1>Reference tables</h1><p class="muted" style="margin-top:0">Grant types, delegation, agent identities, what's deterministic, MCP, token claims, anti-patterns, threats, the errors you'll run into and a glossary.</p>
    <div class="ref-tools" role="search"><input class="ref-filter" id="refFilter" type="search" placeholder="Filter rows, or paste an AADSTS error" aria-label="Filter the reference rows, or paste an AADSTS error message" aria-describedby="refCount"><span class="soft" id="refCount" aria-live="polite"></span></div>
    <div id="refLookup" class="notice info" hidden></div>
    <nav class="ref-nav" aria-label="Reference sections">${REFERENCE.map((s) => `<button class="btn sm" data-jump="${s.id}">${esc(s.title.split(':')[0])}</button>`).join('')}</nav>
    ${REFERENCE.map((s) => `<section class="ref-section" id="ref-${s.id}" aria-labelledby="refh-${s.id}"><h2 id="refh-${s.id}" tabindex="-1">${esc(s.title)}</h2>${s.intro ? `<div class="muted" style="margin-bottom:8px">${s.intro}</div>` : ''}
      <div class="card"><table class="ref" aria-labelledby="refh-${s.id}"><thead><tr>${s.cols.map((c) => `<th scope="col">${c}</th>`).join('')}</tr></thead><tbody>${s.rows.map((r) => `<tr>${r.map((c, i) => `<td>${s.cols[i] === 'Tab' ? (c ? `<a href="#flow/${c}" aria-label="Open the ${esc(flowTitle(c))} tab">Open ▸</a>` : '') : c}</td>`).join('')}</tr>`).join('')}</tbody></table></div></section>`).join('')}`;
  $$('[data-jump]', main).forEach((b) => { b.onclick = () => { const h = $(`#refh-${b.dataset.jump}`); h.scrollIntoView({ behavior: reducedMotion() ? 'auto' : 'smooth' }); h.focus({ preventScroll: true }); }; });
  const total = $$('table.ref tbody tr', main).length;
  $('#refFilter').oninput = (e) => {
    const raw = e.target.value.trim();
    // A pasted error such as "AADSTS50013: Assertion failed..." filters on the code alone.
    const code = raw.match(/AADSTS\s*(\d{5,7})/i)?.[1];
    const q = (code || raw).toLowerCase();
    let shown = 0;
    $$('.ref-section', main).forEach((sec) => {
      let n = 0;
      $$('tbody tr', sec).forEach((tr) => { tr.hidden = q && !tr.textContent.toLowerCase().includes(q); if (!tr.hidden) n++; });
      sec.hidden = q && !n; shown += n;
    });
    $('#refCount').textContent = q ? `${shown} of ${total} rows match${code ? ` AADSTS${code}` : ''}` : '';
    const lk = $('#refLookup');
    if (!code) { lk.hidden = true; lk.innerHTML = ''; return; }
    const flows = aadstsFlows(code);
    lk.hidden = false;
    lk.innerHTML = `${flows.length ? `<b>AADSTS${esc(code)}</b> shows up in ${flows.map((f) => `<a href="#flow/${f.id}">${esc(f.title)}</a>`).join(', ')}. ` : `None of the flows here produce <b>AADSTS${esc(code)}</b>. `}Microsoft's own lookup: <a href="https://login.microsoftonline.com/error?code=${esc(code)}" target="_blank" rel="noopener">login.microsoftonline.com/error?code=${esc(code)}</a>`;
  };
  if (q0) { $('#refFilter').value = q0; $('#refFilter').oninput({ target: $('#refFilter') }); }
  if (anchor) setTimeout(() => $(`#ref-${anchor}`)?.scrollIntoView(), 0);
}

/* ---------- mode, theme, keyboard ---------- */
function setMode(m) {
  if (m === 'live' && !Live.configured) { toast(Live.reachable ? 'The server is up, but no tenant is configured yet. Run provisioning/New-AuthFlowTenant.ps1 first.' : 'Live mode needs the local server. Run npm start in the server folder and open http://localhost:5100', 5000); return; }
  APP.mode = m;
  $$('.mode-switch button').forEach((b) => { const on = b.dataset.mode === m; b.classList.toggle('on', on); b.setAttribute('aria-checked', on); b.tabIndex = on ? 0 : -1; });
  announce(m === 'live' ? 'Live mode. Flows now call the real Entra tenant.' : 'Simulated mode. No network calls.');
  if (APP.player) APP.player.reset();
  else if (APP.route === '#flow/ca-sim') route();
}
function updateLiveStatus() {
  const s = $('#liveStatus');
  s.classList.remove('ok', 'warn');
  if (Live.configured) { s.classList.add('ok'); s.querySelector('.txt').textContent = `Server ready, tenant ${Live.health.tenantId.slice(0, 8)}…`; }
  else if (Live.reachable) { s.classList.add('warn'); s.querySelector('.txt').textContent = 'Server up, no tenant configured'; }
  else s.querySelector('.txt').textContent = location.protocol === 'file:' ? 'Opened from disk, simulation only' : 'Can\'t reach the live server';
  $('#liveBtn').title = Live.configured ? 'Run flows against the real Entra tenant' : 'Needs the local server and a configured tenant';
}
/* Arrow, Home and End move between the options of a tablist or radiogroup and select the new one. */
function rovingKey(e) {
  const group = e.target.closest('[role=tablist], [role=radiogroup]');
  if (!group || !['ArrowLeft', 'ArrowRight', 'ArrowUp', 'ArrowDown', 'Home', 'End'].includes(e.key)) return false;
  const items = $$('[role=tab], [role=radio]', group).filter((b) => !b.disabled);
  const i = items.indexOf(e.target.closest('[role=tab], [role=radio]'));
  if (i < 0 || !items.length) return false;
  e.preventDefault();
  const n = items.length;
  const j = e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : (i + (e.key === 'ArrowRight' || e.key === 'ArrowDown' ? 1 : -1) + n) % n;
  items[j].focus();
  items[j].click();
  return true;
}
/* Below 1400 px, or while presenting, the side menu overlays the page instead of taking width from the diagram. */
const NAV_DRAWER_MQ = window.matchMedia('(max-width: 1399px)');
const isNavDrawer = () => document.body.classList.contains('nav-drawer');
const isNavOpen = () => (isNavDrawer() ? document.body.classList.contains('nav-open') : !document.body.classList.contains('nav-collapsed'));
function setNavOpen(open, moveFocus = false) {
  const b = document.body;
  if (isNavDrawer()) b.classList.toggle('nav-open', open); else b.classList.toggle('nav-collapsed', !open);
  $('#navBtn').setAttribute('aria-expanded', isNavOpen());
  if (!isNavDrawer()) { refitZoom(); return; }
  if (open && moveFocus) ($('#nav .nav-item[aria-current]') || $('#nav .nav-item'))?.focus();
  if (!open && $('#nav').contains(document.activeElement)) $('#navBtn').focus();
}
function syncNav() {
  document.body.classList.toggle('nav-drawer', NAV_DRAWER_MQ.matches || document.body.classList.contains('presenter'));
  document.body.classList.remove('nav-open');
  $('#navBtn').setAttribute('aria-expanded', isNavOpen());
  refitZoom();
}
const activeZoom = () => APP.player?.zoom || APP.archZoom;
/** Layout changed without a resize event the zoom views can rely on, so recompute Fit now. */
function refitZoom() {
  APP.player?.syncLayout();
  const z = activeZoom();
  if (z && z.pref() === 'fit') z.apply();
}
function setPresenter(on) {
  document.body.classList.toggle('presenter', on);
  $('#btnPresent')?.setAttribute('aria-pressed', on);
  syncNav();
  announce(on ? 'Presenter mode on. Press P or Escape to leave.' : 'Presenter mode off.');
}
function openHelp() {
  const d = $('#helpModal');
  if (d.open) return;
  APP.helpReturn = document.activeElement;
  d.showModal();
}
function closeHelp() { const d = $('#helpModal'); if (d.open) d.close(); }
function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  $('#themeBtn').setAttribute('aria-pressed', t === 'dark');
  $('meta[name="theme-color"]')?.setAttribute('content', t === 'dark' ? '#1b1d2b' : '#ebe7fa');
}
function onKey(e) {
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if ($('#helpModal').open) return;
  if (e.key === 'Escape') {
    if (isNavDrawer() && isNavOpen()) { setNavOpen(false); return; }
    if (document.body.classList.contains('presenter')) { setPresenter(false); return; }
  }
  if (rovingKey(e)) return;
  if (e.target.closest('input, textarea, select, [contenteditable]')) return;
  const t = e.target;
  if ((e.key === 'Enter' || e.key === ' ') && t.matches?.('.node[tabindex]')) { e.preventDefault(); t.dispatchEvent(new MouseEvent('click', { bubbles: true })); return; }
  // A focused, scrollable diagram area pans with the arrow keys like any scroll container.
  if (t.matches?.('.zoom-vp') && e.key.startsWith('Arrow')) return;
  if (e.key === '?') { openHelp(); return; }
  if (e.key === 'n' || e.key === 'N') { setNavOpen(!isNavOpen(), true); return; }
  if (e.key === 'p' || e.key === 'P') { setPresenter(!document.body.classList.contains('presenter')); return; }
  const z = activeZoom();
  if (z && (e.key === '+' || e.key === '=')) { z.zoomBy(1.25); return; }
  if (z && (e.key === '-' || e.key === '_')) { z.zoomBy(0.8); return; }
  if (z && e.key === '0') { z.set('fit'); return; }
  const p = APP.player; if (!p) return;
  if (e.key === ' ') { if (t.closest('button, a, summary, [role=button]')) return; e.preventDefault(); p.onPlay(); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); p.step(1); }
  else if (e.key === 'ArrowLeft') { e.preventDefault(); p.step(-1); }
  else if (e.key === 'r' || e.key === 'R') p.reset();
  else if (e.key === 'v' || e.key === 'V') p.setView(APP.view === 'diagram' ? 'sequence' : 'diagram');
  else if (/^[1-5]$/.test(e.key)) { APP.inspTab = INSP_TABS[Number(e.key) - 1].id; p.renderInspector(); }
}

async function init() {
  $('#brandSub').textContent = `${ID.tenantName} identity, delegation and agent sign-in, one request at a time`;
  renderNav();
  initGlossary();
  window.addEventListener('hashchange', route);
  document.addEventListener('keydown', onKey);
  $$('.mode-switch button').forEach((b) => { b.onclick = () => setMode(b.dataset.mode); });
  applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');
  $('#themeBtn').onclick = () => {
    const t = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    applyTheme(t);
    try { localStorage.setItem('authflow-theme', t); } catch { /* ignore */ }
  };
  $('#skipLink').onclick = (e) => { e.preventDefault(); $('#main').focus(); };
  $('#helpBtn').onclick = openHelp;
  $('#navBtn').onclick = () => setNavOpen(!isNavOpen(), true);
  $('#navScrim').onclick = () => setNavOpen(false);
  $('#nav').addEventListener('click', (e) => { if (isNavDrawer() && e.target.closest('a')) setNavOpen(false); });
  document.addEventListener('focusin', (e) => { if (isNavDrawer() && isNavOpen() && !$('#nav').contains(e.target) && e.target !== $('#navBtn')) setNavOpen(false); });
  NAV_DRAWER_MQ.addEventListener?.('change', syncNav);
  syncNav();
  $('#helpClose').onclick = closeHelp;
  const help = $('#helpModal');
  help.onclick = (e) => { if (e.target === help) closeHelp(); };
  help.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); closeHelp(); } });
  help.addEventListener('close', () => { const r = APP.helpReturn; APP.helpReturn = null; if (r && r.isConnected) r.focus(); });
  route();
  await Live.check();
  updateLiveStatus();
  if (APP.player) APP.player.updateControls();
  else if (APP.route === '#flow/ca-sim') route();
}
init();
