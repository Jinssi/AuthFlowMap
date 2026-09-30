'use strict';
/* =====================================================================
   PLAYER: flow page, step playback (simulated and live), inspector.
   ===================================================================== */
const INSP_TABS = [
  { id: 'overview', label: 'Overview' }, { id: 'request', label: 'Request' }, { id: 'response', label: 'Response' },
  { id: 'tokens', label: 'Tokens' }, { id: 'checks', label: 'Checks' },
];

function flowPageHtml(flow) {
  const b = flow.brief;
  const liveCap = flow.live ? `<span class="pill live" title="This flow can run against a real Entra tenant in Live mode">● Runs live</span>` : '<span class="pill">Simulated only</span>';
  const groupName = { standard: 'Standard OAuth / OIDC', access: 'Access, MFA and devices', agent: 'Microsoft Entra Agent ID', mcp: 'MCP & multi-agent' }[flow.group];
  const variants = flow.variants ? `<h3>Variant</h3><div class="variant-row">${flow.variants.map((v, i) => `<label class="actor-chip" title="${esc(v.desc)}"><input type="radio" name="variant" value="${v.id}" ${i ? '' : 'checked'}> ${esc(v.label)}</label>`).join('')}</div><div class="soft" style="font-size:12px;margin-top:4px" id="variantDesc">${esc(flow.variants[0].desc)}</div>` : '';
  return `
  <div class="flow-head">
    <div><h1>${esc(flow.title)}</h1><div class="muted">${esc(flow.subtitle)}</div>
      <div class="tags"><span class="pill accent">${groupName}</span>${liveCap}<span class="pill">${flow.actors.length} components</span><span class="pill" id="stepCountPill"></span></div></div>
  </div>
  <details class="briefing card card-pad" open>
    <summary>Briefing. Read this before you press Start</summary>
    <div class="brief-grid">
      <div><h3>What this shows</h3><div>${b.what}</div>
        <h3>Components involved</h3><div class="actor-chips">${flow.actors.map((a) => `<span class="actor-chip" title="${esc(ACTORS[a].desc)}">${esc(ACTORS[a].name)}</span>`).join('')}</div>${docLinksHtml(flow.id)}</div>
      <div><h3>What has to be set up</h3><ul class="tight">${b.prereqs.map((p) => `<li>${p}</li>`).join('')}</ul>${variants}</div>
      <div><h3>Anti-pattern to avoid</h3><div class="notice bad">${b.antiPattern}</div>
        ${b.verify ? `<h3>Note</h3><div class="notice">${b.verify}</div>` : ''}
        <h3>Legend</h3><div class="legend">${Object.keys(DET).map((d) => detPill(d)).join('')}</div></div>
    </div>
  </details>
  <div class="controls card">
    <button class="btn primary" id="btnPlay" title="Space">▶ Start</button>
    <div class="btn-group"><button class="btn" id="btnBack" title="←">◀ Step</button><button class="btn" id="btnFwd" title="→">Step ▶</button></div>
    <button class="btn" id="btnReset" title="R">↺ Reset</button>
    <div class="btn-group" role="group" aria-label="View"><button class="btn" data-view="diagram">Components</button><button class="btn" data-view="sequence">Sequence</button></div>
    <label class="speed">Speed <input type="range" id="speed" min="0.25" max="3" step="0.25" value="${APP.speed}"><span id="speedVal">${APP.speed}×</span></label>
    <span class="spacer"></span>
    <span class="pill" id="modePill"></span>
    <span class="progress" id="progress"></span>
    <div class="progress-bar"><div id="progressBar"></div></div>
    <div id="liveBanner" style="flex-basis:100%" hidden></div>
  </div>
  <div class="stage-grid">
    <div class="stage-col">
      <div class="stage card"><div class="stage-caption" id="caption"></div><div class="stage-view" id="stageView"></div></div>
      <div class="steps card" id="stepList"></div>
    </div>
    <div class="inspector card" id="inspector"></div>
  </div>`;
}

class Player {
  constructor(flow, root) {
    this.flow = flow; this.root = root; this.steps = []; this.idx = -1; this.playing = false; this.finished = false;
    this.mode = 'sim'; this.variant = flow.variants?.[0]?.id; this.gen = 0; this.stopAnim = null; this.timer = null;
    this.live = { done: false, waiting: false, error: null }; this.viewDirty = false; this.animating = false;
  }
  $(sel) { return this.root.querySelector(sel); }
  mount() {
    this.root.innerHTML = flowPageHtml(this.flow);
    this.$('#btnPlay').onclick = () => this.onPlay();
    this.$('#btnBack').onclick = () => this.step(-1);
    this.$('#btnFwd').onclick = () => this.step(1);
    this.$('#btnReset').onclick = () => this.reset();
    $$('[data-view]', this.root).forEach((b) => { b.onclick = () => this.setView(b.dataset.view); });
    this.$('#speed').oninput = (e) => { APP.speed = Number(e.target.value); this.$('#speedVal').textContent = `${APP.speed}×`; };
    $$('input[name=variant]', this.root).forEach((r) => {
      r.onchange = () => { this.variant = r.value; this.$('#variantDesc').textContent = this.flow.variants.find((v) => v.id === r.value).desc; this.reset(); };
    });
    this.$('#stepList').onclick = (e) => { const b = e.target.closest('[data-i]'); if (b) this.goTo(Number(b.dataset.i)); };
    this.$('#stageView').onclick = (e) => {
      const r = e.target.closest('.seq-row-bg'); if (r) this.goTo(Number(r.dataset.i));
      const n = e.target.closest('.node'); if (n && ACTORS[n.dataset.actor]) toast(`${ACTORS[n.dataset.actor].name}. ${ACTORS[n.dataset.actor].desc}`, 6000);
    };
    this.$('#inspector').onclick = (e) => { const t = e.target.closest('[data-tab]'); if (t && !t.disabled) { APP.inspTab = t.dataset.tab; this.renderInspector(); } };
    this.reset();
  }
  destroy() { this.dead = true; this.clearTimers(); this.gen++; }
  clearTimers() { clearTimeout(this.timer); this.timer = null; if (this.stopAnim) this.stopAnim(); this.stopAnim = null; this.animating = false; }

  /* ----- preparation ----- */
  async prepareSim() {
    this.ctx = await makeSimCtx(this.flow, this.variant);
    this.steps = this.flow.steps(this.ctx).map((s) => normSimStep(s, this.ctx));
    this.mode = 'sim'; this.idx = -1; this.finished = false;
    this.rebuild();
  }
  prepareLive() {
    this.templates = Object.fromEntries(templateSteps(this.flow, this.variant).map((s) => [s.id, s]));
    this.steps = []; this.mode = 'live'; this.idx = -1; this.finished = false;
    this.live = { done: false, waiting: true, error: null };
    this.rebuild();
  }
  async reset() {
    this.clearTimers(); this.gen++; this.liveGen = (this.liveGen || 0) + 1; this.playing = false; this.setBanner('');
    Live.cancel();
    await this.prepareSim();
  }
  rebuild() { this.renderStepList(); this.renderView(); this.update(); }

  /* ----- playback ----- */
  async onPlay() {
    if (this.playing) { this.pause(); return; }
    if (this.idx >= 0 && !this.finished) { this.playing = true; this.updateControls(); if (!this.animating) this.advance(); return; }
    const d = this.$('details.briefing'); if (d) d.open = false;
    if (APP.mode === 'live' && this.flow.live && Live.ready(this.flow.id, this.variant)) { this.startLive(); return; }
    if (APP.mode === 'live') toast(this.flow.live ? 'The server isn\'t configured for this flow, so you\'re seeing the simulation.' : 'This flow only exists as a simulation, so that\'s what runs.', 4000);
    this.clearTimers(); this.gen++;
    await this.prepareSim();
    this.playing = true; this.updateControls(); this.advance();
  }
  startLive() {
    const popup = Live.needsPopup(this.flow.id) ? Live.openPopup() : null;
    this.clearTimers(); this.gen++;
    this.prepareLive(); this.playing = true; this.updateControls();
    const myRun = this.liveGen = (this.liveGen || 0) + 1;
    Live.run(this.flow.id, { variant: this.variant, popup, emit: (ev) => this.pushLive(ev), banner: (html) => this.setBanner(html) })
      .then(() => { if (this.dead || myRun !== this.liveGen) return; this.live.done = true; this.setBanner(''); if (this.live.waiting) this.finish(); else this.update(); })
      .catch((err) => {
        if (this.dead || myRun !== this.liveGen) return;
        this.live.error = err.message || String(err); this.live.done = true;
        this.setBanner(`<div class="notice bad"><b>The live run stopped.</b> ${esc(this.live.error)}</div>`);
        if (popup && !popup.closed) popup.close();
        if (this.live.waiting) this.finish(); else this.update();
      });
  }
  pushLive(ev) {
    if (this.dead) return;
    this.steps.push(normLiveEvent(ev, this.templates[ev.stepId]));
    this.renderStepList();
    if (this.animating) this.viewDirty = true; else this.renderView();
    this.update();
    if (this.live.waiting && this.playing) { this.live.waiting = false; this.advance(); }
  }
  pause() { this.playing = false; clearTimeout(this.timer); this.updateControls(); }
  advance() {
    if (this.idx + 1 < this.steps.length) { this.show(this.idx + 1, true); return; }
    if (this.mode === 'live' && !this.live.done) { this.live.waiting = true; this.updateCaption(); return; }
    this.finish();
  }
  finish() { this.playing = false; this.finished = true; this.live.waiting = false; this.updateControls(); this.updateCaption(); }
  step(delta) {
    this.pause();
    const i = Math.min(this.steps.length - 1, Math.max(0, this.idx + delta));
    if (this.steps.length) this.show(i, false);
  }
  goTo(i) { this.pause(); this.show(i, false); }
  show(i, auto) {
    this.clearTimers();
    if (this.viewDirty) { this.viewDirty = false; this.renderView(); }
    this.idx = i; this.finished = false; this.update();
    const st = this.steps[i]; if (!st) return;
    const gen = ++this.gen, sp = APP.speed;
    this.animating = true;
    const done = () => {
      if (gen !== this.gen) return;
      this.animating = false; this.stopAnim = null;
      const p = this.$('#packet'); if (p) p.style.display = 'none';
      if (this.viewDirty) { this.viewDirty = false; this.renderView(); this.update(); }
      if (auto && this.playing) this.timer = setTimeout(() => this.advance(), 1900 / sp);
      else if (i === this.steps.length - 1 && (this.mode === 'sim' || this.live.done)) { this.finished = true; this.updateControls(); }
    };
    if (st.from === st.to) { this.timer = setTimeout(done, 1200 / sp); return; }
    const svg = this.$('#stageView svg');
    const path = APP.view === 'diagram' ? svg.querySelector(`#e-${st.from}-${st.to}`) : svg.querySelector(`#sa-${i}`);
    this.stopAnim = animatePacket(svg, path, packetLabel(st), 1400 / sp, done);
  }
  setView(v) { APP.view = v; this.clearTimers(); this.gen++; this.renderView(); this.update(); if (this.playing) this.timer = setTimeout(() => this.advance(), 600); }

  /* ----- rendering ----- */
  renderStepList() {
    const el = this.$('#stepList');
    if (!this.steps.length) { el.innerHTML = `<div class="insp-empty">${this.mode === 'live' ? 'Waiting for the first live event…' : ''}</div>`; return; }
    el.innerHTML = this.steps.map((s, i) => `<button class="step-item" data-i="${i}"><span class="num">${i + 1}</span><span><span class="t">${esc(s.title)}</span>
      <span class="sub">${esc(ACTORS[s.from]?.name || s.from)} → ${esc(ACTORS[s.to]?.name || s.to)} ${detPill(s.det)}${this.mode === 'live' ? `<span class="src-tag ${s.src === 'live' ? '' : 'sim'}">${s.src === 'live' ? 'REAL' : 'SIM'}</span>` : ''}</span></span></button>`).join('');
    this.$('#stepCountPill').textContent = `${this.steps.length} steps`;
  }
  renderView() {
    const view = this.$('#stageView');
    const steps = this.steps.length ? this.steps : (this.mode === 'live' ? Object.values(this.templates || {}) : []);
    view.innerHTML = APP.view === 'diagram' ? buildDiagram(this.flow, steps) : `<div class="seq-wrap">${buildSequence(this.flow, this.steps)}</div>`;
    $$('[data-view]', this.root).forEach((b) => b.classList.toggle('on', b.dataset.view === APP.view));
  }
  update() {
    const i = this.idx, st = this.steps[i];
    $$('.step-item', this.root).forEach((b, k) => {
      b.classList.toggle('done', k < i); b.classList.toggle('current', k === i);
      b.classList.toggle('err', this.steps[k].status === 'error' && k <= i);
    });
    const cur = this.$(`.step-item[data-i="${i}"]`), list = this.$('#stepList');
    if (cur && list) {
      const top = cur.offsetTop;
      if (top < list.scrollTop || top + cur.offsetHeight > list.scrollTop + list.clientHeight) list.scrollTop = top - list.clientHeight / 3;
    }
    const svg = this.$('#stageView svg');
    if (svg && APP.view === 'diagram') {
      $$('.node', svg).forEach((n) => n.classList.remove('sender', 'receiver', 'working'));
      $$('.edge', svg).forEach((e) => e.classList.remove('done', 'active', 'err'));
      this.steps.forEach((s, k) => { if (k < i && s.from !== s.to) svg.querySelector(`#e-${s.from}-${s.to}`)?.classList.add('done'); });
      const lbl = svg.querySelector('#edgeLbl');
      if (st) {
        const nf = svg.querySelector(`.node[data-actor="${st.from}"]`), nt = svg.querySelector(`.node[data-actor="${st.to}"]`);
        let mid;
        if (st.from === st.to) { nf?.classList.add('working'); const p = (this.flow.layout[st.from] || [500, 440]); mid = [p[0], p[1] + NODE_H / 2 + 20]; }
        else {
          nf?.classList.add('sender'); nt?.classList.add('receiver');
          const e = svg.querySelector(`#e-${st.from}-${st.to}`);
          if (e) { e.classList.add('active'); if (st.status === 'error') e.classList.add('err'); e.setAttribute('marker-end', 'url(#ah-a)'); mid = e.dataset.mid.split(',').map(Number); }
          $$('.edge:not(.active)', svg).forEach((x) => x.setAttribute('marker-end', 'url(#ah)'));
        }
        if (mid && lbl) {
          const text = trunc(st.label, 44), w = text.length * 6.4 + 16;
          lbl.style.display = ''; lbl.setAttribute('transform', `translate(${mid[0] - w / 2},${mid[1] - 10})`);
          lbl.querySelector('rect').setAttribute('width', w); const t = lbl.querySelector('text'); t.textContent = text; t.setAttribute('x', 8);
        }
      } else if (lbl) lbl.style.display = 'none';
    }
    if (svg && APP.view === 'sequence') {
      this.steps.forEach((s, k) => {
        const a = svg.querySelector(`#sa-${k}`), l = svg.querySelector(`#sl-${k}`), bg = svg.querySelector(`.seq-row-bg[data-i="${k}"]`);
        a?.setAttribute('class', `seq-arrow ${k > i ? 'future' : k === i ? 'current' : ''} ${s.status === 'error' && k <= i ? 'err' : ''}`);
        a?.setAttribute('marker-end', k === i ? 'url(#ah-a)' : 'url(#ah)');
        l?.setAttribute('class', `seq-label ${k > i ? 'future' : ''}`);
        bg?.classList.toggle('current', k === i);
      });
      const row = svg.querySelector(`.seq-row-bg[data-i="${i}"]`);
      const wrap = this.$('.seq-wrap');
      if (row && wrap) { const r = row.getBoundingClientRect(), w = wrap.getBoundingClientRect(); if (r.top < w.top || r.bottom > w.bottom) wrap.scrollTop += r.top - w.top - w.height / 3; }
    }
    this.updateCaption(); this.renderInspector(); this.updateControls();
  }
  updateCaption() {
    const c = this.$('#caption'), st = this.steps[this.idx];
    if (this.live.waiting && this.mode === 'live' && this.playing) {
      c.innerHTML = `<span><b>Waiting for the next live event.</b> <span class="muted">The demo records real requests as they happen and replays them slowly enough to talk over.</span></span>`;
    } else if (this.finished && this.idx >= this.steps.length - 1 && this.steps.length) {
      c.innerHTML = `<span><b>Done. ${this.steps.length} steps.</b> <span class="muted">Click any step, use ◀ ▶ or switch the view to go through it again.</span></span>${this.live.error ? `<span class="pill warn">${esc(trunc(this.live.error, 60))}</span>` : ''}`;
    } else if (st) {
      c.innerHTML = `${detPill(st.det)}<span><span class="big">${this.idx + 1}. ${esc(st.title)}</span><br><span class="muted">${esc(actorLabel(st.from))} → ${esc(actorLabel(st.to))} · ${esc(st.label)}</span></span>`;
    } else {
      c.innerHTML = `<span><b>Ready.</b> <span class="muted">Press Start or Space. The ${APP.view === 'diagram' ? 'component diagram already shows every hop this flow will take' : 'sequence diagram already lists every message in order'}.</span></span>`;
    }
  }
  updateControls() {
    const b = this.$('#btnPlay');
    b.textContent = this.playing ? '⏸ Pause' : (this.idx >= 0 && !this.finished ? '▶ Resume' : (this.finished ? '↻ Restart' : '▶ Start'));
    this.$('#btnBack').disabled = this.idx <= 0;
    this.$('#btnFwd').disabled = this.idx >= this.steps.length - 1;
    const n = this.steps.length;
    this.$('#progress').textContent = n ? `Step ${Math.max(0, this.idx + 1)} / ${n}${this.mode === 'live' && !this.live.done ? '+' : ''}` : '';
    this.$('#progressBar').style.width = n ? `${((this.idx + 1) / n) * 100}%` : '0';
    const mp = this.$('#modePill');
    const liveOk = this.flow.live && Live.ready(this.flow.id, this.variant);
    if (APP.mode === 'live') { mp.className = `pill ${liveOk ? 'live' : 'warn'}`; mp.textContent = liveOk ? '● LIVE against a real Entra tenant' : 'No live version, showing the simulation'; }
    else { mp.className = 'pill'; mp.textContent = 'Simulated, no network calls'; }
  }
  setBanner(html) { const b = this.$('#liveBanner'); if (!b) return; b.hidden = !html; b.innerHTML = html || ''; }
  renderInspector() {
    const box = this.$('#inspector'), st = this.steps[this.idx];
    if (!st) {
      box.innerHTML = `<div class="insp-head"><b>Inspector</b><div class="route">Each step\'s request, response, decoded tokens and checks show up here.</div></div>
        <div class="insp-body explain"><p>${esc(this.flow.subtitle)}</p><p class="muted">Press <kbd>Space</kbd> or <b>Start</b>. Keys <kbd>1</kbd> to <kbd>5</kbd> switch the inspector tabs.</p>
        <h3>Legend</h3>${Object.keys(DET).map((d) => `<p>${detPill(d)} <span class="muted">${esc(DET[d].desc)}</span></p>`).join('')}</div>`;
      return;
    }
    const avail = { overview: true, request: !!st.req, response: !!st.res, tokens: st.tokens.length > 0, checks: st.checks.length > 0 };
    const counts = { tokens: st.tokens.length, checks: st.checks.length };
    const tab = avail[APP.inspTab] ? APP.inspTab : 'overview';
    const src = st.src === 'live' ? '<span class="src-tag">REAL</span>' : '<span class="src-tag sim">SIMULATED</span>';
    let body = '';
    if (tab === 'overview') {
      const kv = st.kv && Object.keys(st.kv).length ? `<h3>Values</h3><div class="kv">${Object.entries(st.kv).filter(([k]) => k !== 'prompt' || true).map(([k, v]) => `<span class="k">${esc(k)}</span><span class="mono" style="word-break:break-all">${esc(dispVal(k, typeof v === 'string' ? v : JSON.stringify(v)))}</span>`).join('')}</div>` : '';
      const dc = st.kv && st.kv.user_code ? `<div class="device-code-box"><div class="muted">Open <a href="${esc(st.kv.verification_uri || 'https://microsoft.com/devicelogin')}" target="_blank" rel="noopener">${esc(st.kv.verification_uri || 'microsoft.com/devicelogin')}</a> and type</div><div class="code">${esc(st.kv.user_code)}</div></div>` : '';
      const quick = [st.req ? `<span class="k">Request</span><span class="mono">${esc(st.req.method || '')} ${esc(trunc(st.req.url, 70))}</span>` : '', st.res ? `<span class="k">Response</span><span class="mono">${esc(st.res.status)} ${esc(st.res.statusText || '')}</span>` : '', counts.tokens ? `<span class="k">Tokens</span><span>${counts.tokens}, on the Tokens tab</span>` : '', counts.checks ? `<span class="k">Checks</span><span>${counts.checks}, on the Checks tab</span>` : ''].join('');
      body = `<div class="explain">${st.desc ? `<p>${st.desc}</p>` : ''}${st.why ? `<div class="why"><b>Why it matters.</b> ${st.why}</div>` : ''}
        ${st.note ? `<div class="notice ${st.status === 'error' ? 'bad' : 'info'}" style="margin:8px 0">${esc(st.note)}</div>` : ''}${dc}${kv}
        ${quick ? `<h3>In this step</h3><div class="kv">${quick}</div>` : ''}
        <h3>Who decides</h3><p>${detPill(st.det)} <span class="muted">${esc(DET[st.det]?.desc || '')}</span></p></div>`;
    } else if (tab === 'request') body = renderRequest(st.req);
    else if (tab === 'response') body = renderResponse(st.res);
    else if (tab === 'tokens') body = `<p class="soft" style="font-size:12px;margin-top:0">Signatures are masked. The highlighted rows are the claims worth pointing at.</p>${renderTokens(st.tokens)}`;
    else if (tab === 'checks') body = renderChecks(st.checks);
    box.innerHTML = `<div class="insp-head"><div style="display:flex;justify-content:space-between;gap:8px"><b>${this.idx + 1}. ${esc(st.title)}</b>${src}</div>
      <div class="route">${esc(actorLabel(st.from))} <b>→</b> ${esc(actorLabel(st.to))} ${detPill(st.det)} ${st.status === 'error' ? '<span class="pill warn">error</span>' : st.status === 'pending' ? '<span class="pill">pending</span>' : ''}</div></div>
      <div class="insp-tabs">${INSP_TABS.map((t, k) => `<button data-tab="${t.id}" class="${t.id === tab ? 'on' : ''}" ${avail[t.id] ? '' : 'disabled'} title="Key ${k + 1}">${t.label}${counts[t.id] ? `<span class="count">${counts[t.id]}</span>` : ''}</button>`).join('')}</div>
      <div class="insp-body">${body}</div>`;
  }
}
