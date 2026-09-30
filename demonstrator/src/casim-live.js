'use strict';
/* =====================================================================
   CONDITIONAL ACCESS SIMULATOR: Live mode through Graph What If.
   ===================================================================== */
const CAS_COUNTRY = { office: 'FI', home: 'FI', abroad: 'US', blocked: 'KP' };
const CAS_APPS = { m365: ['00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000'], azure: ['797f4846-ba00-4fd7-ba43-dac1f8f63013'] };
let casLast = null;

function casBuildRequest(s) {
  const h = Live.health || {};
  const human = isHuman(s);
  const subject = human ? 'user' : (h.whatIfSubjects?.agent ? 'agent' : 'workload');
  const context = human && s.authContext === 'c1'
    ? { type: 'authContext', value: h.stepUpAuthContext || 'c1' }
    : { type: 'app', appIds: s.app === 'finance' ? [h.ids?.apiClientId].filter(Boolean) : CAS_APPS[s.app] };
  const conditions = { country: CAS_COUNTRY[s.location] };
  if (human) {
    Object.assign(conditions, {
      devicePlatform: s.platform, clientAppType: { browser: 'browser', desktop: 'mobileAppsAndDesktopClients', legacy: 'other' }[s.client],
      signInRiskLevel: s.signInRisk, userRiskLevel: s.userRisk, deviceCodeFlow: s.flowType === 'devicecode',
    });
    if (s.device !== 'unknown') { conditions.deviceCompliant = s.device === 'compliant'; conditions.deviceTrustType = { compliant: 'AzureAd', hybrid: 'ServerAd', registered: 'Workplace' }[s.device]; }
  } else conditions.servicePrincipalRiskLevel = s.agentRisk;
  return { subject, context, conditions };
}

function casRenderLive(s) {
  const box = $('#casLive'); if (!box) return;
  const ready = APP.mode === 'live' && Live.ready('ca-sim');
  if (!ready) {
    box.innerHTML = `<h3 style="margin-top:0">Your tenant</h3><p class="muted" style="margin:0">${APP.mode === 'live' ? 'The server has no What If configuration. Provisioning writes DEMO_USER_ID and grants the daemon Policy.Read.ConditionalAccess.' : 'Switch to Live to send these same conditions to Graph\'s What If API and see what your real policies decide.'}</p>`;
    return;
  }
  const req = casBuildRequest(s), key = JSON.stringify(req);
  const shown = casLast && casLast.key === key ? casLast : null;
  const subjNote = s.subject === 'admin' || s.subject === 'guest' ? `<div class="notice" style="margin:8px 0">What If runs as the demo user. The ${s.subject} choice only changes the offline model.</div>` : '';
  box.innerHTML = `<div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><h3 style="margin:0">Your tenant, via Graph What If</h3>
      <button class="btn primary sm" id="casLiveBtn">Evaluate in my tenant</button></div>${subjNote}
    <details style="margin-top:8px"><summary class="soft" style="cursor:pointer">Request that will be sent</summary><pre class="http">${jsonHtml(req)}</pre></details>
    <div id="casLiveOut">${shown ? shown.html : ''}</div>`;
}

async function casRunLive(s) {
  const out = $('#casLiveOut'); if (!out) return;
  out.innerHTML = '<p class="muted">Asking Graph…</p>';
  const req = casBuildRequest(s), key = JSON.stringify(req);
  try {
    const r = await fetch('/api/live/ca-whatif', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ runId: `run_${randStr(20, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')}`, ...req }) });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error_description || j.error || `HTTP ${r.status}`);
    const pols = j.policies || [];
    const applied = pols.filter((p) => p.policyApplies && p.state === 'enabled');
    const blocked = applied.some((p) => (p.grantControls?.builtInControls || []).includes('block'));
    const needs = [...new Set(applied.flatMap((p) => [...(p.grantControls?.builtInControls || []).filter((c) => c !== 'block'), p.grantControls?.authenticationStrength?.displayName].filter(Boolean)))];
    const reportOnly = pols.filter((p) => p.policyApplies && p.state !== 'enabled');
    const verdict = blocked ? 'Blocked' : needs.length ? `Allowed if the user satisfies: ${needs.join(', ')}` : applied.length ? 'Allowed, session controls only' : 'No enabled policy applies';
    const sess = (p) => Object.entries(p.sessionControls || {}).filter(([, v]) => v && (v.isEnabled || typeof v === 'object')).map(([k]) => k).join(', ');
    const html = `<div class="notice ${blocked ? 'bad' : 'info'}" style="margin:10px 0"><b>${esc(verdict)}.</b> ${applied.length} enabled polic${applied.length === 1 ? 'y applies' : 'ies apply'}${reportOnly.length ? `, plus ${reportOnly.length} in report-only or disabled` : ''}.</div>
      ${pols.map((p) => `<div class="pol-row ${p.policyApplies ? (p.state === 'enabled' ? ((p.grantControls?.builtInControls || []).includes('block') ? 'bad' : 'ok') : 'na') : 'na'}">
        <span class="pol-id">${esc(p.state === 'enabled' ? 'on' : p.state === 'enabledForReportingButNotEnforced' ? 'report' : 'off')}</span><span class="pol-name">${esc(p.displayName)}</span>
        <span class="pol-res">${p.policyApplies ? `Applies: ${esc([...(p.grantControls?.builtInControls || []), p.grantControls?.authenticationStrength?.displayName].filter(Boolean).join(` ${p.grantControls?.operator || 'AND'} `) || sess(p) || 'no grant controls')}` : esc(p.analysisReasons || 'Does not apply')}</span></div>`).join('') || '<p class="muted">The tenant has no Conditional Access policies.</p>'}`;
    casLast = { key, html };
    out.innerHTML = html;
  } catch (e) {
    out.innerHTML = `<div class="notice bad" style="margin-top:10px"><b>What If failed.</b> ${esc(e.message)}</div>`;
  }
}
