'use strict';
/* =====================================================================
   CONDITIONAL ACCESS SIMULATOR: evaluation and page rendering.
   ===================================================================== */
function casEvaluate(s) {
  const results = CAS_POLICIES.map((p) => {
    const reason = p.when(s);
    const grant = typeof p.grant === 'function' ? p.grant(s) : p.grant;
    return { p, applies: !reason, reason, grant, session: p.session || [] };
  });
  const applied = results.filter((r) => r.applies);
  const blockers = [], prompts = new Set(), sessions = new Set(), unmet = [];
  for (const r of applied) {
    r.session.forEach((x) => sessions.add(x));
    if (r.grant.block) { blockers.push({ id: r.p.id, why: r.grant.why || r.p.name }); r.status = 'block'; continue; }
    const list = r.grant.all || r.grant.any || [];
    const okList = list.filter((c) => CAS_CONTROLS[c].ok(s));
    const satisfied = r.grant.any ? okList.length > 0 : okList.length === list.length;
    r.status = satisfied ? 'ok' : 'unmet';
    if (!satisfied) unmet.push({ id: r.p.id, need: list.filter((c) => !CAS_CONTROLS[c].ok(s)).map((c) => CAS_CONTROLS[c].label).join(r.grant.any ? ' or ' : ' and ') });
    else (r.grant.any ? okList.slice(0, 1) : okList).forEach((c) => { if (CAS_CONTROLS[c].prompt && CAS_CONTROLS[c].prompt(s)) prompts.add(CAS_CONTROLS[c].label); });
  }
  let verdict, code = '', experience;
  if (blockers.length) {
    verdict = 'blocked'; code = 'AADSTS53003';
    experience = `Blocked by ${blockers.map((b) => b.id).join(', ')}. ${isHuman(s) ? 'The user sees "You cannot access this right now".' : 'The agent gets no token.'}`;
  } else if (unmet.length) {
    verdict = 'blocked'; code = unmet.some((u) => /device/i.test(u.need)) ? 'AADSTS53000' : 'AADSTS53003';
    experience = `Blocked, because the user can't satisfy ${unmet.map((u) => `${u.id} (${u.need})`).join('; ')}.`;
  } else if (sessions.size && [...sessions].some((x) => /restrictions/i.test(x))) {
    verdict = 'restricted';
    experience = `Allowed with limits${prompts.size ? ` after ${[...prompts].join(', ')}` : ''}.`;
  } else if (prompts.size) {
    verdict = 'prompt'; experience = `Allowed after ${[...prompts].join(', ')}.`;
  } else {
    verdict = 'silent'; experience = isHuman(s) && managed(s) ? 'Allowed silently. The device PRT already carries MFA.' : 'Allowed without a prompt.';
  }
  const claims = {};
  if (verdict !== 'blocked' && isHuman(s)) {
    claims.amr = s.method === 'passkey' ? ['mfa'] : prompts.size || s.method === 'push' ? ['pwd', 'mfa'] : ['pwd'];
    if (s.device !== 'unknown') claims.deviceid = '<device object ID>';
    if (s.authContext === 'c1') claims.acrs = ['c1'];
  }
  return { results, verdict, code, experience, sessions: [...sessions], claims };
}

const VERDICT_TEXT = { silent: 'Allowed silently', prompt: 'Allowed after a prompt', restricted: 'Allowed with restrictions', blocked: 'Blocked' };

function renderCaSim(main, flow) {
  const b = flow.brief;
  const st = { ...CAS_DEFAULT };
  main.innerHTML = `
    <div class="flow-head"><div><h1>${esc(flow.title)}</h1><div class="muted">${esc(flow.subtitle)}</div>
      <div class="tags"><span class="pill accent">Access, MFA and devices</span><span class="pill live">● Runs live</span><span class="pill">${CAS_POLICIES.length} sample policies</span></div></div></div>
    <details class="briefing card card-pad"><summary>Briefing. Read this before you start</summary>
      <div class="brief-grid"><div><h3>What this shows</h3><div>${b.what}</div></div>
      <div><h3>What has to be set up</h3><ul class="tight">${b.prereqs.map((p) => `<li>${p}</li>`).join('')}</ul></div>
      <div><h3>Anti-pattern to avoid</h3><div class="notice bad">${b.antiPattern}</div><h3>Note</h3><div class="notice">${b.verify}</div></div></div></details>
    <div class="casim-grid">
      <div class="card card-pad casim-inputs">
        <h3 style="margin-top:0">Scenarios</h3><div class="casim-presets">${CAS_PRESETS.map((p, i) => `<button class="btn sm" data-preset="${i}">${esc(p.label)}</button>`).join('')}</div>
        <div id="casInputs"></div>
      </div>
      <div class="casim-out">
        <div class="card card-pad verdict" id="casVerdict"></div>
        <div class="card card-pad" id="casLive"></div>
        <div class="card card-pad"><h3 style="margin-top:0">Sample policies, offline model</h3><div id="casPolicies"></div></div>
      </div>
    </div>`;
  const draw = () => {
    $('#casInputs').innerHTML = CAS_INPUTS.filter((i) => (i.human ? isHuman(st) : true) && (i.agent ? !isHuman(st) : true)).map((i) => `
      <div class="seg-row"><div class="seg-label">${esc(i.label)}</div><div class="seg">${i.opts.map(([v, l]) => `<button class="${st[i.key] === v ? 'on' : ''}" data-k="${i.key}" data-v="${v}">${esc(l)}</button>`).join('')}</div></div>`).join('');
    const r = casEvaluate(st);
    $('#casVerdict').className = `card card-pad verdict v-${r.verdict}`;
    $('#casVerdict').innerHTML = `<div class="v-head"><span class="v-title">${VERDICT_TEXT[r.verdict]}</span>${r.code ? `<span class="pill warn">${r.code}</span>` : ''}</div>
      <p style="margin:6px 0 10px">${esc(r.experience)}</p>
      ${r.sessions.length ? `<div class="kv"><span class="k">Session</span><span>${r.sessions.map(esc).join('<br>')}</span></div>` : ''}
      ${Object.keys(r.claims).length ? `<div class="kv" style="margin-top:6px"><span class="k">Token gets</span><span class="mono">${Object.entries(r.claims).map(([k, v]) => `${k}: ${esc(JSON.stringify(v))}`).join('<br>')}</span></div>` : ''}`;
    $('#casPolicies').innerHTML = r.results.map((x) => {
      const g = x.grant.block ? 'Block' : (x.grant.all || x.grant.any || []).map((c) => CAS_CONTROLS[c].label).join(x.grant.any ? ' or ' : ' and ') || 'Session controls only';
      const cls = !x.applies ? 'na' : x.status === 'ok' ? 'ok' : 'bad';
      return `<div class="pol-row ${cls}"><span class="pol-id">${x.p.id}</span><span class="pol-name">${esc(x.p.name)}${x.p.preview ? ' <span class="pill">preview</span>' : ''}</span>
        <span class="pol-res">${!x.applies ? esc(CAS_REASONS[x.reason] || x.reason) : x.status === 'block' ? 'Applies: block' : x.status === 'unmet' ? `Applies: needs ${esc(g)}` : `Applies: ${esc(g)}`}</span></div>`;
    }).join('');
    casRenderLive(st);
  };
  main.onclick = (e) => {
    const s = e.target.closest('[data-k]');
    if (s) { st[s.dataset.k] = s.dataset.v; draw(); return; }
    const p = e.target.closest('[data-preset]');
    if (p) { Object.assign(st, CAS_DEFAULT, CAS_PRESETS[Number(p.dataset.preset)].s); draw(); return; }
    if (e.target.closest('#casLiveBtn')) casRunLive(st);
  };
  draw();
}
