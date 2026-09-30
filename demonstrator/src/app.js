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
  { id: 'ref', title: 'Reference' },
];

let toastTimer = 0;
function toast(msg, ms = 3000) {
  const t = $('#toast'); t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), ms);
}

function renderNav() {
  const item = (href, label, badge = '') => `<button class="nav-item" data-href="${href}"><span>${esc(label)}</span>${badge}</button>`;
  let html = '';
  for (const g of GROUPS) {
    html += `<div class="nav-group"><div class="nav-group-title">${g.title}</div>`;
    if (g.id === 'overview') html += item('#architecture', 'Architecture');
    else if (g.id === 'ref') html += item('#reference', 'Reference tables') + item('#reference/docs', 'Documentation links');
    else FLOWS.filter((f) => f.group === g.id).forEach((f) => { html += item(`#flow/${f.id}`, f.title, f.live ? `<span class="nav-badge" title="Can run live against Entra">LIVE</span>` : ''); });
    html += '</div>';
  }
  $('#nav').innerHTML = html;
  $('#nav').onclick = (e) => { const b = e.target.closest('[data-href]'); if (b) location.hash = b.dataset.href; };
}

function route() {
  const h = location.hash || '#architecture';
  APP.route = h;
  $$('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.href === h));
  if (APP.player) { APP.player.destroy(); APP.player = null; Live.cancel(); }
  const main = $('#main'); main.scrollTop = 0;
  if (h.startsWith('#flow/')) {
    const flow = FLOWS.find((f) => f.id === h.slice(6));
    if (!flow) { main.innerHTML = '<p>Unknown flow.</p>'; return; }
    if (flow.kind === 'simulator') renderCaSim(main, flow);
    else { APP.player = new Player(flow, main); APP.player.mount(); }
  } else if (h === '#reference' || h.startsWith('#reference/')) renderReference(main, h.split('/')[1]);
  else renderArchitecture(main);
  main.focus({ preventScroll: true });
}

/* ---------- architecture ---------- */
function renderArchitecture(main) {
  const W = 1180, H = 660;
  const zones = ZONES.map((z) => `<rect class="zone-rect" x="${z.x}" y="20" width="${z.w}" height="${H - 30}" rx="14"/><text class="zone-label" x="${z.x + z.w / 2}" y="44" text-anchor="middle">${esc(z.label)}</text>`).join('');
  const edges = ARCH_EDGES.map(([a, b]) => { const [x1, y1] = ARCH_POS[a], [x2, y2] = ARCH_POS[b]; return `<line class="arch-edge" data-a="${a}" data-b="${b}" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}"/>`; }).join('');
  const nodes = Object.keys(ARCH_POS).map((id) => nodeSvg(id, ARCH_POS[id][0], ARCH_POS[id][1], 'clickable')).join('');
  const flowCard = (f) => `<button class="card card-pad" style="text-align:left;cursor:pointer" data-href="#flow/${f.id}"><div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(f.title)}</b>${f.live ? '<span class="pill live">LIVE</span>' : ''}</div><div class="muted" style="font-size:12.5px;margin-top:4px">${esc(f.subtitle)}</div></button>`;
  main.innerHTML = `
    <h1>Architecture overview</h1>
    <p class="muted" style="max-width:900px;margin-top:0">Every component that shows up in any of the flows. <b>Click one</b> to see what it does and which flows use it. Each flow tab opens with a briefing, and <b>Start</b> plays the messages hop by hop.</p>
    <div class="arch-layout">
      <div class="card arch-svg-wrap"><svg viewBox="0 0 ${W} ${H}" id="archSvg" role="img" aria-label="Architecture">${zones}<g>${edges}</g><g>${nodes}</g></svg>
        <div class="legend" style="padding:0 8px 6px">${Object.keys(DET).map((d) => `${detPill(d)} <span class="soft" style="font-size:12px;margin-right:10px">${esc(DET[d].label)}</span>`).join('')}</div></div>
      <div class="arch-side card card-pad" id="archSide">
        <h2>Three layers</h2>
        <p><b>Entra ID</b> is the identity layer. It signs in people and workloads, applies policy and <i>issues signed tokens</i>.</p>
        <p><b>Clients and agents</b> <i>ask</i> for tokens. A browser app has no credential. Everything else proves itself with a certificate, a managed identity or a federated credential, then sends the token as a Bearer header.</p>
        <p><b>Resources</b> such as APIs, Graph and MCP servers <i>check</i> each token's signature, audience, expiry and scopes or roles before deciding what data to return.</p>
        <div class="notice info">The AI model sits next to all of this, not inside it. It picks tools. Protocol and policy decide identity and access.</div>
      </div>
    </div>
    <h2 style="margin-top:20px">Flow catalogue</h2>
    ${['standard', 'access', 'agent', 'mcp'].map((g) => `<h3>${GROUPS.find((x) => x.id === g).title}</h3><div class="grid-3">${FLOWS.filter((f) => f.group === g).map(flowCard).join('')}</div>`).join('')}
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
  main.querySelectorAll('[data-href]').forEach((b) => { b.onclick = () => { location.hash = b.dataset.href; }; });
}
function selectArchActor(id) {
  const a = ACTORS[id]; const svg = $('#archSvg');
  $$('.node', svg).forEach((n) => n.classList.toggle('selected', n.dataset.actor === id));
  $$('.arch-edge', svg).forEach((l) => l.classList.toggle('hl', l.dataset.a === id || l.dataset.b === id));
  const flows = FLOWS.filter((f) => f.actors.includes(id));
  $('#archSide').innerHTML = `<h2>${esc(a.name)}</h2><div class="pill" style="margin-bottom:8px">${esc(a.role)}</div>
    <p>${esc(a.desc)}</p><h3>Key facts</h3><ul class="tight">${a.facts.map((f) => `<li>${esc(f)}</li>`).join('')}</ul>
    <h3>Appears in ${flows.length} flow${flows.length === 1 ? '' : 's'}</h3><div style="display:flex;flex-direction:column;gap:6px">${flows.map((f) => `<button class="btn sm" style="justify-content:flex-start" data-href="#flow/${f.id}">${esc(f.title)}</button>`).join('') || '<span class="soft">Architecture only</span>'}</div>`;
  $$('#archSide [data-href]').forEach((b) => { b.onclick = () => { location.hash = b.dataset.href; }; });
}

/* ---------- reference ---------- */
function renderReference(main, anchor) {
  main.innerHTML = `<h1>Reference tables</h1><p class="muted" style="margin-top:0">Grant types, delegation, agent identities, what's deterministic, MCP, token claims, anti-patterns and the errors you'll run into.</p>
    <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><input class="ref-filter" id="refFilter" type="search" placeholder="Filter rows, try OBO or aud" aria-label="Filter rows"></div>
    <div class="ref-nav">${REFERENCE.map((s) => `<button class="btn sm" data-jump="${s.id}">${esc(s.title.split(':')[0])}</button>`).join('')}</div>
    ${REFERENCE.map((s) => `<section class="ref-section" id="ref-${s.id}"><h2>${esc(s.title)}</h2>${s.intro ? `<div class="muted" style="margin-bottom:8px">${s.intro}</div>` : ''}
      <div class="card"><table class="ref"><thead><tr>${s.cols.map((c) => `<th>${c}</th>`).join('')}</tr></thead><tbody>${s.rows.map((r) => `<tr>${r.map((c, i) => `<td>${s.cols[i] === 'Tab' ? (c ? `<a href="#flow/${c}">Open ▸</a>` : '') : c}</td>`).join('')}</tr>`).join('')}</tbody></table></div></section>`).join('')}`;
  $$('[data-jump]', main).forEach((b) => { b.onclick = () => $(`#ref-${b.dataset.jump}`).scrollIntoView({ behavior: 'smooth' }); });
  $('#refFilter').oninput = (e) => {
    const q = e.target.value.trim().toLowerCase();
    $$('table.ref tbody tr', main).forEach((tr) => { tr.hidden = q && !tr.textContent.toLowerCase().includes(q); });
  };
  if (anchor) setTimeout(() => $(`#ref-${anchor}`)?.scrollIntoView(), 0);
}

/* ---------- mode, theme, keyboard ---------- */
function setMode(m) {
  if (m === 'live' && !Live.configured) { toast(Live.reachable ? 'The server is up, but no tenant is configured yet. Run provisioning/New-AuthFlowTenant.ps1 first.' : 'Live mode needs the local server. Run npm start in the server folder and open http://localhost:5100', 5000); return; }
  APP.mode = m;
  $$('.mode-switch button').forEach((b) => { const on = b.dataset.mode === m; b.classList.toggle('on', on); b.setAttribute('aria-checked', on); });
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
function onKey(e) {
  if (e.target.closest('input, textarea, select') || e.ctrlKey || e.metaKey || e.altKey) return;
  if (e.key === 'Escape') { $('#helpModal').hidden = true; return; }
  if (e.key === '?') { $('#helpModal').hidden = false; return; }
  if (e.key === 'n' || e.key === 'N') { document.body.classList.toggle('nav-collapsed'); return; }
  const p = APP.player; if (!p) return;
  if (e.key === ' ') { e.preventDefault(); p.onPlay(); }
  else if (e.key === 'ArrowRight') { e.preventDefault(); p.step(1); }
  else if (e.key === 'ArrowLeft') { e.preventDefault(); p.step(-1); }
  else if (e.key === 'r' || e.key === 'R') p.reset();
  else if (e.key === 'v' || e.key === 'V') p.setView(APP.view === 'diagram' ? 'sequence' : 'diagram');
  else if (/^[1-5]$/.test(e.key)) { APP.inspTab = INSP_TABS[Number(e.key) - 1].id; p.renderInspector(); }
}

async function init() {
  $('#brandSub').textContent = `${ID.tenantName} identity, delegation and agent sign-in, one request at a time`;
  renderNav();
  window.addEventListener('hashchange', route);
  document.addEventListener('keydown', onKey);
  $$('.mode-switch button').forEach((b) => { b.onclick = () => setMode(b.dataset.mode); });
  $('#themeBtn').onclick = () => {
    const t = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('authflow-theme', t); } catch { /* ignore */ }
  };
  $('#helpBtn').onclick = () => { $('#helpModal').hidden = false; };
  $('#navBtn').onclick = () => document.body.classList.toggle('nav-collapsed');
  $('#helpClose').onclick = () => { $('#helpModal').hidden = true; };
  $('#helpModal').onclick = (e) => { if (e.target.id === 'helpModal') $('#helpModal').hidden = true; };
  route();
  await Live.check();
  updateLiveStatus();
  if (APP.player) APP.player.updateControls();
  else if (APP.route === '#flow/ca-sim') route();
}
init();
