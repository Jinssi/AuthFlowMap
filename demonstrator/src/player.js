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
  const groupName = GROUPS.find((g) => g.id === flow.group)?.title || '';
  const previewPill = flow.preview ? `<span class="pill warn" title="${esc(flow.preview)}">Uses preview features</span>` : '';
  const variants = flow.variants ? `<h3>Variant</h3><div class="variant-row">${flow.variants.map((v, i) => `<label class="actor-chip" title="${esc(v.desc)}"><input type="radio" name="variant" value="${v.id}" ${i ? '' : 'checked'}> ${esc(v.label)}</label>`).join('')}</div><div class="soft" style="font-size:12px;margin-top:4px" id="variantDesc">${esc(flow.variants[0].desc)}</div>` : '';
  return `
  <div class="flow-head">
    <div><h1>${esc(flow.title)}</h1><div class="muted">${esc(flow.subtitle)}</div>
      <div class="tags"><span class="pill accent">${groupName}</span>${liveCap}${previewPill}<span class="pill">${flow.actors.length} components</span><span class="pill" id="stepCountPill"></span></div></div>
  </div>
  <details class="briefing card card-pad" open>
    <summary>Briefing. Read this before you press Start</summary>
    <div class="brief-grid">
      <div><h3>What this shows</h3><div data-gloss>${b.what}</div>
        <h3>Components involved</h3><div class="actor-chips">${flow.actors.map((a) => `<span class="actor-chip" title="${esc(ACTORS[a].desc)}">${esc(ACTORS[a].name)}</span>`).join('')}</div>${docLinksHtml(flow.id)}</div>
      <div><h3>What has to be set up</h3><ul class="tight" data-gloss>${b.prereqs.map((p) => `<li>${p}</li>`).join('')}</ul>${variants}</div>
      <div><h3>Anti-pattern to avoid</h3><div class="notice bad">${b.antiPattern}</div>
        ${b.verify ? `<h3>Note</h3><div class="notice">${b.verify}</div>` : ''}${threatsHtml(flow.id)}
        <h3>Legend</h3><div class="legend">${Object.keys(DET).map((d) => detPill(d)).join('')}</div></div>
    </div>
  </details>
  <div class="controls card" role="group" aria-label="Playback controls">
    <button class="btn primary" id="btnPlay" title="Space" aria-keyshortcuts="Space"><span aria-hidden="true">▶</span> Start</button>
    <div class="btn-group"><button class="btn" id="btnBack" title="Previous step, key ←" aria-label="Previous step" aria-keyshortcuts="ArrowLeft"><span aria-hidden="true">◀</span> Step</button><button class="btn" id="btnFwd" title="Next step, key →" aria-label="Next step" aria-keyshortcuts="ArrowRight">Step <span aria-hidden="true">▶</span></button></div>
    <button class="btn" id="btnReset" title="Reset, key R" aria-label="Reset flow" aria-keyshortcuts="R"><span aria-hidden="true">↺</span> Reset</button>
    <div class="btn-group" role="group" aria-label="Diagram view, key V"><button class="btn" data-view="diagram" aria-pressed="false">Components</button><button class="btn" data-view="sequence" aria-pressed="false">Sequence</button></div>
    <button class="btn" id="btnPresent" aria-pressed="${document.body.classList.contains('presenter')}" title="Presenter mode: larger text, no side menu or briefing. Key P" aria-keyshortcuts="P"><span aria-hidden="true">⛶</span> Present</button>
    <label class="speed">Speed <input type="range" id="speed" min="0.25" max="3" step="0.25" value="${APP.speed}" aria-valuetext="${APP.speed} times"><span id="speedVal" aria-hidden="true">${APP.speed}×</span></label>
    <span class="spacer"></span>
    <span class="pill" id="modePill"></span>
    <span class="progress" id="progress"></span>
    <div class="progress-bar" role="progressbar" aria-label="Flow progress" aria-valuemin="0" aria-valuemax="0" aria-valuenow="0"><div id="progressBar"></div></div>
    <div id="liveBanner" role="status" style="flex-basis:100%" hidden></div>
  </div>
  <div class="stage-grid">
    <div class="stage-col">
      <section class="stage card" aria-label="Diagram"><div class="stage-top"><div class="stage-caption" id="caption"></div>${zoomBarHtml()}</div><div class="stage-view" id="stageView" role="group" aria-label="Diagram area. When it is larger than the space, drag or use the arrow keys to pan, and Ctrl with the mouse wheel to zoom"></div></section>
      <section class="steps card" id="stepList" aria-label="Steps"></section>
    </div>
    <aside class="inspector card" id="inspector" aria-label="Step inspector"></aside>
  </div>`;
}

class Player {
  constructor(flow, root, opts = {}) {
    this.flow = flow; this.root = root; this.steps = []; this.idx = -1; this.playing = false; this.finished = false;
    this.mode = 'sim'; this.variant = flow.variants?.[0]?.id; this.gen = 0; this.stopAnim = null; this.timer = null;
    this.live = { done: false, waiting: false, error: null }; this.viewDirty = false; this.animating = false;
    // Deep link options from #flow/<id>?variant=&step=&view=
    this.opts = opts;
    if (flow.variants?.some((v) => v.id === opts.variant)) this.variant = opts.variant;
    if (opts.view === 'diagram' || opts.view === 'sequence') APP.view = opts.view;
  }
  $(sel) { return this.root.querySelector(sel); }
  mount() {
    this.root.innerHTML = flowPageHtml(this.flow);
    glossarize(this.$('.brief-grid'));
    const vr = this.$(`input[name=variant][value="${this.variant}"]`);
    if (vr && !vr.checked) { vr.checked = true; this.$('#variantDesc').textContent = this.flow.variants.find((v) => v.id === this.variant).desc; }
    this.$('#btnPlay').onclick = () => this.onPlay();
    this.$('#btnBack').onclick = () => this.step(-1);
    this.$('#btnFwd').onclick = () => this.step(1);
    this.$('#btnReset').onclick = () => this.reset();
    $$('[data-view]', this.root).forEach((b) => { b.onclick = () => this.setView(b.dataset.view); });
    this.$('#speed').oninput = (e) => { APP.speed = Number(e.target.value); this.$('#speedVal').textContent = `${APP.speed}×`; e.target.setAttribute('aria-valuetext', `${APP.speed} times`); };
    $$('input[name=variant]', this.root).forEach((r) => {
      r.onchange = () => { this.variant = r.value; this.$('#variantDesc').textContent = this.flow.variants.find((v) => v.id === r.value).desc; this.reset(); };
    });
    this.$('#stepList').onclick = (e) => {
      const b = e.target.closest('[data-i]'); if (b) { this.goTo(Number(b.dataset.i)); return; }
      const a = e.target.closest('[data-act]');
      if (a?.dataset.act === 'link') copyText(stepLink(this), 'a link to this step');
      else if (a?.dataset.act === 'export') runExport(this);
    };
    this.$('#stageView').onclick = (e) => {
      const r = e.target.closest('.seq-row-bg'); if (r) this.goTo(Number(r.dataset.i));
      const n = e.target.closest('.node'); if (n && ACTORS[n.dataset.actor]) toast(`${ACTORS[n.dataset.actor].name}. ${ACTORS[n.dataset.actor].desc}`, 6000);
    };
    this.$('#inspector').onclick = (e) => {
      const t = e.target.closest('[data-tab]'); if (t && !t.disabled) { APP.inspTab = t.dataset.tab; this.renderInspector(); return; }
      const c = e.target.closest('[data-copy]'), req = this.steps[this.idx]?.req;
      if (c && req) copyText(c.dataset.copy === 'curl' ? curlCommand(req) : psCommand(req), c.dataset.copy === 'curl' ? 'the request as curl' : 'the request as PowerShell');
    };
    this.$('#btnPresent').onclick = () => setPresenter(!document.body.classList.contains('presenter'));
    this.zoom = new ZoomView(this.$('#stageView'), this.$('.zoom-bar'), { key: APP.view });
    // The inspector sticks just under the controls bar, which changes height when it wraps.
    const ctr = this.$('.controls');
    this.syncLayout = () => {
      if (this.dead) return;
      const ch = `${ctr.offsetHeight}px`, mh = `${this.root.clientHeight}px`, s = this.root.style;
      if (s.getPropertyValue('--controls-h') === ch && s.getPropertyValue('--main-h') === mh) return;
      s.setProperty('--controls-h', ch); s.setProperty('--main-h', mh);
      if (this.zoom.pref() === 'fit') this.zoom.apply();
    };
    if (window.ResizeObserver) { this.ro = new ResizeObserver(() => this.syncLayout()); this.ro.observe(ctr); this.ro.observe(this.root); }
    this.syncLayout();
    this.reset().then(() => {
      const n = parseInt(this.opts.step, 10);
      if (this.dead || !(n >= 1 && n <= this.steps.length)) return;
      const d = this.$('details.briefing'); if (d) d.open = false;
      this.goTo(n - 1);
    });
  }
  destroy() {
    this.dead = true; this.clearTimers(); this.gen++; this.zoom?.destroy();
    this.ro?.disconnect(); this.root.style.removeProperty('--controls-h'); this.root.style.removeProperty('--main-h');
  }
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
    if (APP.mode === 'live' && this.canRunLive()) { this.startLive(); return; }
    if (APP.mode === 'live') toast(this.simOnlyVariant() ? 'This variant only exists as a simulation, so that\'s what runs.' : this.flow.live ? 'The server isn\'t configured for this flow, so you\'re seeing the simulation.' : 'This flow only exists as a simulation, so that\'s what runs.', 4000);
    this.clearTimers(); this.gen++;
    await this.prepareSim();
    this.playing = true; this.updateControls(); this.advance();
  }
  simOnlyVariant() { return !!this.flow.variants?.find((v) => v.id === this.variant)?.simOnly; }
  canRunLive() { return this.flow.live && !this.simOnlyVariant() && Live.ready(this.flow.id, this.variant); }
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
  finish() { this.playing = false; this.finished = true; this.live.waiting = false; this.markDone(); this.updateControls(); this.updateCaption(); this.renderInspector(); announce(`Flow finished, ${this.steps.length} steps.`); }
  markDone() { if (this.steps.length && this.idx >= this.steps.length - 1) markFlowDone(this.flow.id); }
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
    announce(`Step ${i + 1} of ${this.steps.length}: ${st.title}. ${actorLabel(st.from)} to ${actorLabel(st.to)}.`);
    const gen = ++this.gen, sp = APP.speed;
    this.animating = true;
    const done = () => {
      if (gen !== this.gen) return;
      this.animating = false; this.stopAnim = null;
      const p = this.$('#packet'); if (p) p.style.display = 'none';
      if (this.viewDirty) { this.viewDirty = false; this.renderView(); this.update(); }
      if (auto && this.playing) this.timer = setTimeout(() => this.advance(), 1900 / sp);
      else if (i === this.steps.length - 1 && (this.mode === 'sim' || this.live.done)) { this.finished = true; this.markDone(); this.updateControls(); this.renderInspector(); }
    };
    if (st.from === st.to) { this.timer = setTimeout(done, 1200 / sp); return; }
    const svg = this.$('#stageView .stage-svg');
    const path = APP.view === 'diagram' ? svg.querySelector(`#e-${st.from}-${st.to}`) : svg.querySelector(`#sa-${i}`);
    this.stopAnim = animatePacket(svg, path, packetLabel(st), 1400 / sp, done);
  }
  setView(v) { APP.view = v; this.clearTimers(); this.gen++; this.renderView(); this.update(); if (this.playing) this.timer = setTimeout(() => this.advance(), 600); }

  /* ----- rendering ----- */
  renderStepList() {
    const el = this.$('#stepList');
    if (!this.steps.length) { el.innerHTML = `<div class="insp-empty">${this.mode === 'live' ? 'Waiting for the first live event…' : ''}</div>`; return; }
    el.innerHTML = `<ol class="step-ol">${this.steps.map((s, i) => `<li><button class="step-item" data-i="${i}"><span class="num" aria-hidden="true">${i + 1}</span><span><span class="sr-only">Step ${i + 1}: </span><span class="t">${esc(s.title)}</span>
      <span class="sub">${esc(ACTORS[s.from]?.name || s.from)} <span aria-label="to">→</span> ${esc(ACTORS[s.to]?.name || s.to)} ${detPill(s.det)}${stagePills(s)}${this.mode === 'live' ? `<span class="src-tag ${s.src === 'live' ? '' : 'sim'}">${s.src === 'live' ? 'REAL' : 'SIM'}</span>` : ''}</span></span></button></li>`).join('')}</ol>
      <div class="step-actions"><button class="btn sm" data-act="link" title="Copies a link that opens this flow at the current step, variant and view">Copy link to this step</button><button class="btn sm" data-act="export" title="Downloads every step as JSON. Secrets, codes and token signatures are replaced with placeholders">Export run (JSON)</button></div>`;
    this.$('#stepCountPill').textContent = `${this.steps.length} steps`;
  }
  renderView() {
    const view = this.$('#stageView');
    const steps = this.steps.length ? this.steps : (this.mode === 'live' ? Object.values(this.templates || {}) : []);
    view.innerHTML = APP.view === 'diagram' ? buildDiagram(this.flow, steps) : buildSequence(this.flow, this.steps);
    fitSvgText(view);
    this.zoom.configure(APP.view === 'diagram' ? { key: 'diagram', font: 14, fitHeight: true } : { key: 'sequence', font: 13.5, fitHeight: false });
    $$('[data-view]', this.root).forEach((b) => { const on = b.dataset.view === APP.view; b.classList.toggle('on', on); b.setAttribute('aria-pressed', on); });
  }
  update() {
    const i = this.idx, st = this.steps[i];
    $$('.step-item', this.root).forEach((b, k) => {
      b.classList.toggle('done', k < i); b.classList.toggle('current', k === i);
      b.classList.toggle('err', this.steps[k].status === 'error' && k <= i);
      if (k === i) b.setAttribute('aria-current', 'step'); else b.removeAttribute('aria-current');
    });
    const cur = this.$(`.step-item[data-i="${i}"]`), list = this.$('#stepList');
    if (cur && list) {
      const top = cur.offsetTop;
      if (top < list.scrollTop || top + cur.offsetHeight > list.scrollTop + list.clientHeight) list.scrollTop = top - list.clientHeight / 3;
    }
    const svg = this.$('#stageView .stage-svg');
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
          lbl.style.display = '';
          const t = lbl.querySelector('text'); t.textContent = trunc(st.label, 44); t.setAttribute('x', 8);
          const w = fitLabel(lbl.querySelector('rect'), t);
          lbl.setAttribute('transform', `translate(${mid[0] - w / 2},${mid[1] - 10})`);
        }
      } else if (lbl) lbl.style.display = 'none';
      // The visible SENDING / RECEIVING / PROCESSING tag comes first in each node, so it leads the name as well.
      $$('.node', svg).forEach((n) => {
        const state = n.classList.contains('sender') ? 'Sending' : n.classList.contains('receiver') ? 'Receiving' : n.classList.contains('working') ? 'Processing' : '';
        n.setAttribute('aria-label', state ? `${state}: ${n.dataset.label}` : n.dataset.label);
      });
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
      const wrap = this.$('#stageView'), headH = this.$('.seq-sticky')?.offsetHeight || 0;
      if (row && wrap) {
        const r = row.getBoundingClientRect(), w = wrap.getBoundingClientRect(), top = w.top + headH;
        if (r.top < top || r.bottom > w.bottom) wrap.scrollTop += r.top - top - (w.bottom - top) / 3;
      }
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
    const [glyph, word] = this.playing ? ['⏸', 'Pause'] : (this.idx >= 0 && !this.finished ? ['▶', 'Resume'] : (this.finished ? ['↻', 'Restart'] : ['▶', 'Start']));
    b.innerHTML = `<span aria-hidden="true">${glyph}</span> ${word}`;
    this.$('#btnBack').disabled = this.idx <= 0;
    this.$('#btnFwd').disabled = this.idx >= this.steps.length - 1;
    const n = this.steps.length;
    this.$('#progress').textContent = n ? `Step ${Math.max(0, this.idx + 1)} / ${n}${this.mode === 'live' && !this.live.done ? '+' : ''}` : '';
    this.$('#progressBar').style.width = n ? `${((this.idx + 1) / n) * 100}%` : '0';
    const pb = this.$('.progress-bar'); pb.setAttribute('aria-valuemax', n); pb.setAttribute('aria-valuenow', Math.max(0, this.idx + 1)); pb.setAttribute('aria-valuetext', n ? `Step ${Math.max(0, this.idx + 1)} of ${n}` : 'Not started');
    const mp = this.$('#modePill');
    const liveOk = this.canRunLive();
    if (APP.mode === 'live') { mp.className = `pill ${liveOk ? 'live' : 'warn'}`; mp.textContent = liveOk ? '● LIVE against a real Entra tenant' : this.flow.live && this.simOnlyVariant() ? 'Simulation only for this variant' : 'No live version, showing the simulation'; }
    else { mp.className = 'pill'; mp.textContent = 'Simulated, no network calls'; }
    this.syncLayout?.();
  }
  setBanner(html) { const b = this.$('#liveBanner'); if (!b) return; b.hidden = !html; b.innerHTML = html || ''; }
  recapHtml() {
    const s = this.steps;
    const toks = [...new Set(s.flatMap((x) => x.tokens.map((t) => t.label || t.field)).filter(Boolean))];
    const checks = s.flatMap((x) => x.checks.map((c) => (typeof c === 'string' ? { ok: true } : c)));
    const failed = checks.filter((c) => c.ok === false).length, errs = s.filter((x) => x.status === 'error').length;
    const actors = new Set(s.flatMap((x) => [x.from, x.to])).size;
    const noAt = s.findIndex((x) => x.checks.some((c) => checkObj(c).ok === false) || (x.status !== 'pending' && (x.res ? x.res.status >= 400 : x.status === 'error')));
    let said = '<li><b>Who said no:</b> nobody. Every component accepted what it was given.</li>';
    if (noAt >= 0) {
      const x = s[noAt], gs = stepStages(x), bad = x.checks.find((c) => checkObj(c).ok === false);
      const g = bad && !gs.includes('issue') ? (checkKind(bad) === 'token' ? 'validate' : 'authorize') : gs[0];
      const who = x.decider || (x.from === x.to || x.res ? x.from : x.to);
      const later = s[s.length - 1].status !== 'error' && !(s[s.length - 1].res?.status >= 400);
      said = `<li><b>Who said no:</b> ${esc(actorLabel(who))}${g ? `, at the ${STAGES[g].short} stage` : ''}, in step ${noAt + 1} (${esc(x.title)}).${later ? ' The run carried on after that.' : ''}</li>`;
    }
    return `<div class="recap"><h3>Recap</h3><ul class="tight">
      <li>${s.length} steps between ${actors} components.</li>
      <li>${toks.length ? `Tokens: ${toks.map(esc).join(', ')}.` : 'No tokens in this run.'}</li>
      ${checks.length ? `<li>${checks.length} checks, ${failed ? `${failed} failed` : 'all passed'}.</li>` : ''}
      ${said}
      ${errs ? `<li>${errs === 1 ? 'One step ends' : `${errs} steps end`} in an error. Open it to see what was rejected and why.</li>` : ''}
    </ul><p><b>Avoid.</b> ${this.flow.brief.antiPattern}</p></div>`;
  }
  renderInspector() {
    const box = this.$('#inspector');
    keepFocus(box, () => this.renderInspectorHtml(box), '[role=tab][aria-selected=true]');
  }
  renderInspectorHtml(box) {
    const st = this.steps[this.idx];
    if (!st) {
      box.innerHTML = `<div class="insp-head"><h2 class="insp-title">Inspector</h2><div class="route">Each step\'s request, response, decoded tokens and checks show up here.</div></div>
        <div class="insp-body explain"><p>${esc(this.flow.subtitle)}</p><p class="muted">Press <kbd>Space</kbd> or <b>Start</b>. Keys <kbd>1</kbd> to <kbd>5</kbd> switch the inspector tabs.</p>
        <h3>Legend</h3>${Object.keys(DET).map((d) => `<p>${detPill(d)} <span class="muted">${esc(DET[d].desc)}</span></p>`).join('')}
        <h3>Stages</h3>${Object.keys(STAGES).map((g) => `<p>${stagePills({ stage: g })} <span class="muted">${esc(STAGES[g].desc)}</span></p>`).join('')}</div>`;
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
      body = `<div class="explain">${this.finished && this.idx === this.steps.length - 1 ? this.recapHtml() : ''}${st.desc ? `<p>${st.desc}</p>` : ''}${st.why ? `<div class="why"><b>Why it matters.</b> ${st.why}</div>` : ''}
        ${st.note ? `<div class="notice ${st.status === 'error' ? 'bad' : 'info'}" style="margin:8px 0">${esc(st.note)}</div>` : ''}${dc}${kv}
        ${quick ? `<h3>In this step</h3><div class="kv">${quick}</div>` : ''}
        <h3>Who decides</h3><p>${detPill(st.det)} <span class="muted">${esc(DET[st.det]?.desc || '')}</span></p>
        ${stepStages(st).map((g) => `<p>${stagePills({ stage: g })} <span class="muted">${esc(STAGES[g].desc)}</span></p>`).join('')}</div>`;
    } else if (tab === 'request') body = `${renderRequest(st.req)}<div class="insp-actions" role="group" aria-label="Copy this request"><button class="btn sm" data-copy="curl">Copy as curl</button><button class="btn sm" data-copy="pwsh">Copy as PowerShell</button><span class="soft">Secrets and tokens become placeholders.</span></div>`;
    else if (tab === 'response') body = renderResponse(st.res);
    else if (tab === 'tokens') body = `<p class="soft" style="font-size:12px;margin-top:0">Signatures are masked. The highlighted rows are the claims worth pointing at.</p>${renderTokens(st.tokens)}`;
    else if (tab === 'checks') body = renderChecks(st.checks, st);
    box.innerHTML = `<div class="insp-head"><div style="display:flex;justify-content:space-between;gap:8px"><h2 class="insp-title">${this.idx + 1}. ${esc(st.title)}</h2>${src}</div>
      <div class="route">${esc(actorLabel(st.from))} <b aria-label="to">→</b> ${esc(actorLabel(st.to))} ${detPill(st.det)}${stagePills(st)} ${st.status === 'error' ? '<span class="pill warn">error</span>' : st.status === 'pending' ? '<span class="pill">pending</span>' : ''}</div></div>
      <div class="insp-tabs" role="tablist" aria-label="Inspector views">${INSP_TABS.map((t, k) => { const on = t.id === tab; return `<button role="tab" id="itab-${t.id}" data-tab="${t.id}" class="${on ? 'on' : ''}" aria-selected="${on}" aria-controls="inspPanel" tabindex="${on ? 0 : -1}" ${avail[t.id] ? '' : 'disabled'} title="Key ${k + 1}" aria-keyshortcuts="${k + 1}">${t.label}${counts[t.id] ? `<span class="count"><span class="sr-only">, </span>${counts[t.id]}</span>` : ''}</button>`; }).join('')}</div>
      <div class="insp-body" id="inspPanel" role="tabpanel" aria-labelledby="itab-${tab}" tabindex="0">${body}</div>`;
  }
}
