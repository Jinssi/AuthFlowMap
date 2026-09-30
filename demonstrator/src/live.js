'use strict';
/* =====================================================================
   LIVE MODE: talks to the local AuthFlow server (same origin) and to Entra ID.
   Tokens stay in memory. Everything put into trace events is masked first.
   ===================================================================== */
const Live = {
  health: null, reachable: false, runId: null, aborted: false, mcpSession: null,

  async check() {
    if (location.protocol === 'file:') { this.reachable = false; return; }
    try {
      const r = await fetch('/api/health', { cache: 'no-store' });
      if (!r.ok) throw new Error(r.status);
      this.health = await r.json(); this.reachable = true;
    } catch { this.reachable = false; this.health = null; }
  },
  get configured() { return !!(this.reachable && this.health && this.health.live); },
  ready(flowId, variant) {
    if (!this.configured) return false;
    const f = this.health.flows?.[flowId];
    if (f && typeof f === 'object') return !!f[variant || 'secret'];
    return !!f;
  },
  needsPopup(flowId) {
    return ['auth-code-pkce', 'obo', 'agent-obo', 'mcp-auth', 'step-up', 'aitm', 'device-sso'].includes(flowId) || (flowId === 'mcp-obo' && !this.mcpSession);
  },
  openPopup() {
    const w = window.open('about:blank', 'authflow-signin', 'width=520,height=700');
    if (w) { try { w.document.title = 'Signing in…'; w.document.body.innerHTML = '<p style="font:14px Segoe UI,sans-serif;padding:20px">Preparing the Entra ID sign-in…</p>'; } catch { /* ignore */ } }
    return w;
  },
  cancel() { this.aborted = true; },

  /* ---------- helpers ---------- */
  maskForm(form) {
    const out = {};
    for (const [k, v] of Object.entries(form)) {
      if (k === 'client_secret') out[k] = '••••••••[redacted]';
      else if (['code', 'code_verifier', 'refresh_token', 'device_code', 'assertion', 'client_assertion'].includes(k)) out[k] = isJwt(v) ? maskToken(v) : `${String(v).slice(0, 6)}…[redacted]`;
      else out[k] = v;
    }
    return out;
  },
  tokensFrom(obj, fields = ['access_token', 'id_token']) {
    return fields.filter((f) => isJwt(obj?.[f])).map((f) => { const d = decodeJwt(obj[f]); return { label: f, field: f, masked: maskToken(obj[f]), header: d?.header, payload: d?.payload }; });
  },
  maskJson(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    const out = Array.isArray(obj) ? [] : {};
    for (const [k, v] of Object.entries(obj)) out[k] = ['access_token', 'id_token', 'refresh_token'].includes(k) && typeof v === 'string' ? maskToken(v) : (v && typeof v === 'object' ? this.maskJson(v) : v);
    return out;
  },
  bearerTok(raw, label) { const d = decodeJwt(raw); return { label, field: 'Authorization: Bearer', masked: maskToken(raw), header: d?.header, payload: d?.payload }; },
  sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  guard(o) { if (this.aborted || (o && o.runId !== this.runId)) throw new Error('Run was reset'); },
  async drain(emit, cursor) {
    const r = await fetch(`/api/trace/${cursor.runId}?since=${cursor.n}`, { cache: 'no-store' });
    const j = await r.json();
    (j.events || []).forEach((e) => emit(e));
    cursor.n += (j.events || []).length;
    return j;
  },
  async readBody(r) { const t = await r.text(); try { return JSON.parse(t); } catch { return t; } },
  pickHeaders(r, names) { const o = {}; names.forEach((n) => { const v = r.headers.get(n); if (v) o[n] = v; }); return o; },

  /* ---------- entry point ---------- */
  async run(flowId, opts) {
    this.aborted = false;
    this.runId = `run_${randStr(20, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')}`;
    const runId = this.runId;
    const emit = (ev) => { if (!this.aborted && this.runId === runId) opts.emit({ ts: new Date().toISOString(), status: 'ok', ...ev }); };
    const o = { ...opts, emit, runId, cursor: { n: 0, runId } };
    switch (flowId) {
      case 'client-credentials': case 'device-code': case 'agent-autonomous': case 'id-protection': return this.runServerFlow(flowId, o);
      case 'step-up': return this.runStepUp(o);
      case 'aitm': return this.runMethods(o);
      case 'device-sso': return this.runDevice(o);
      case 'auth-code-pkce': return this.runAuthCode(o);
      case 'obo': return this.runObo(o);
      case 'agent-obo': return this.runAgentObo(o);
      case 'mcp-auth': return this.runMcpAuth(o);
      case 'mcp-obo': return this.runMcpObo(o);
      default: throw new Error('Flow has no live implementation');
    }
  },

  async runServerFlow(flowId, o) {
    const r = await fetch(`/api/live/${flowId}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ runId: o.runId, variant: o.variant }) });
    if (!r.ok) { const b = await this.readBody(r); throw new Error(b?.error_description || b?.error || `Server returned ${r.status}`); }
    for (;;) {
      this.guard(o);
      const j = await this.drain((ev) => {
        o.emit(ev);
        if (ev.stepId === 'dc-code-res' && ev.data?.user_code) {
          o.banner(`<div class="notice info" style="display:flex;gap:16px;align-items:center;flex-wrap:wrap"><span><b>Your turn.</b> On your phone or in another browser, open <a href="${esc(ev.data.verification_uri)}" target="_blank" rel="noopener">${esc(ev.data.verification_uri)}</a> and type this code</span><span class="device-code-box" style="margin:0;padding:4px 14px"><span class="code">${esc(ev.data.user_code)}</span></span></div>`);
        }
        if (ev.stepId === 'dc-token-res') o.banner('');
      }, o.cursor);
      if (j.error) throw new Error(j.error);
      if (j.done) return;
      await this.sleep(600);
    }
  },

  /** Real auth code + PKCE in a popup. Emits the same step ids as the simulated flows. */
  async signIn(p, o, { scope, client = 'browser', extraQuery = {} }) {
    const h = this.health, popup = o.popup;
    if (!popup) throw new Error('The sign-in popup was blocked. Allow popups for this page and press Start again.');
    const verifier = randStr(64, PKCE_ALPHABET), challenge = await sha256b64url(verifier), state = randStr(22), nonce = uuid();
    o.emit({ stepId: `${p}-pkce`, from: client, to: client, label: 'PKCE verifier + challenge', determinism: 'protocol', data: { code_verifier: `${verifier.slice(0, 6)}…, kept in memory only`, code_challenge: challenge, method: 'S256', state, nonce } });
    const authority = `https://login.microsoftonline.com/${h.tenantId}`;
    const q = { client_id: h.spaClientId, response_type: 'code', redirect_uri: h.redirectUri, response_mode: 'query', scope, state, nonce, code_challenge: challenge, code_challenge_method: 'S256', prompt: 'select_account', ...extraQuery };
    const url = `${authority}/oauth2/v2.0/authorize?${new URLSearchParams(q)}`;
    o.emit({ stepId: `${p}-authz`, from: client, to: 'entra', label: 'GET /authorize', determinism: 'protocol', request: { method: 'GET', url, headers: {} } });
    o.banner('<div class="notice info"><b>Your turn.</b> Finish signing in in the popup. The flow picks up again by itself.</div>');
    popup.location.href = url;
    const cb = await new Promise((resolve, reject) => {
      const onMsg = (e) => {
        if (e.origin !== location.origin || e.data?.type !== 'authflow-callback') return;
        cleanup(); resolve(e.data);
      };
      const iv = setInterval(() => { if (this.aborted || o.runId !== this.runId) { cleanup(); reject(new Error('Run was reset')); } else if (popup.closed) { cleanup(); reject(new Error('The sign-in window closed before sign-in finished.')); } }, 500);
      const to = setTimeout(() => { cleanup(); reject(new Error('Sign-in timed out')); }, 5 * 60 * 1000);
      const cleanup = () => { window.removeEventListener('message', onMsg); clearInterval(iv); clearTimeout(to); };
      window.addEventListener('message', onMsg);
    });
    o.banner('');
    if (cb.error) {
      o.emit({ stepId: `${p}-code`, from: 'entra', to: client, label: `error: ${cb.error}`, status: 'error', note: cb.error_description, response: { status: 302, statusText: 'Found', headers: { location: `${h.redirectUri}?error=${cb.error}` } } });
      throw new Error(cb.error_description || cb.error);
    }
    o.emit({ stepId: `${p}-signin`, from: 'entra', to: 'user', label: 'Sign-in + MFA', determinism: 'human', note: 'The user signed in and did MFA in the popup, on the Entra ID page.' });
    o.emit({ stepId: `${p}-code`, from: 'entra', to: client, label: '302 ?code&state', determinism: 'protocol', response: { status: 302, statusText: 'Found', headers: { location: `${h.redirectUri}?code=${cb.code.slice(0, 6)}…[redacted]&state=${cb.state}` } } });
    o.emit({ stepId: `${p}-state`, from: client, to: client, label: 'Verify state', determinism: 'protocol', checks: [{ name: 'state matches stored value', ok: cb.state === state, detail: state }] });
    if (cb.state !== state) throw new Error('The state value doesn\'t match, so this could be a forged callback');
    const tokenUrl = `${authority}/oauth2/v2.0/token`;
    const form = { client_id: h.spaClientId, grant_type: 'authorization_code', code: cb.code, redirect_uri: h.redirectUri, code_verifier: verifier, scope };
    o.emit({ stepId: `${p}-token-req`, from: client, to: 'entra', label: 'POST /token (code + verifier)', determinism: 'protocol', request: { method: 'POST', url: tokenUrl, headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: location.origin }, body: this.maskForm(form) } });
    const r = await fetch(tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form) });
    const j = await this.readBody(r);
    const idt = decodeJwt(j?.id_token);
    o.emit({ stepId: `${p}-token-res`, from: 'entra', to: client, label: r.ok ? '200 tokens' : `${r.status} ${j?.error || ''}`, status: r.ok ? 'ok' : 'error', note: r.ok ? undefined : j?.error_description,
      response: { status: r.status, statusText: r.statusText, headers: { 'content-type': r.headers.get('content-type') || '' }, body: this.maskJson(j) }, tokens: r.ok ? this.tokensFrom(j) : [],
      checks: r.ok ? [{ name: 'PKCE: Entra accepted the code_verifier', ok: true }, { name: 'id_token nonce matches', ok: idt?.payload?.nonce === nonce }, { name: 'id_token aud = this client', ok: idt?.payload?.aud === h.spaClientId }] : [] });
    if (!r.ok) throw new Error(j?.error_description || j?.error || 'Token request failed');
    return j.access_token;
  },

  async runAuthCode(o) {
    o.emit({ stepId: 'ac-start', from: 'user', to: 'browser', label: 'Click "Sign in"', determinism: 'human' });
    const at = await this.signIn('ac', o, { scope: this.health.scopes.graph });
    this.guard(o);
    const url = 'https://graph.microsoft.com/v1.0/me?$select=displayName,userPrincipalName,id,jobTitle';
    o.emit({ stepId: 'ac-graph-req', from: 'browser', to: 'graph', label: 'GET /me (Bearer AT)', request: { method: 'GET', url, headers: { Authorization: `Bearer ${maskToken(at)}` } }, tokens: [this.bearerTok(at, 'Access token (aud = Graph)')] });
    const r = await fetch(url, { headers: { Authorization: `Bearer ${at}` } });
    const b = await this.readBody(r);
    o.emit({ stepId: 'ac-graph-res', from: 'graph', to: 'browser', label: `${r.status} profile`, status: r.ok ? 'ok' : 'error', response: { status: r.status, statusText: r.statusText, headers: { 'content-type': r.headers.get('content-type') || '' }, body: b } });
  },

  async callServer(o, { reqStep, resStep, from, to, labelReq, method, path, token, tokLabel, body }) {
    const headers = { Authorization: `Bearer ${token}`, 'X-Run-Id': o.runId };
    if (body) headers['Content-Type'] = 'application/json';
    o.emit({ stepId: reqStep, from, to, label: labelReq, request: { method, url: `${location.origin}${path}`, headers: { ...headers, Authorization: `Bearer ${maskToken(token)}` }, body }, tokens: [this.bearerTok(token, tokLabel)] });
    const r = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const b = await this.readBody(r);
    await this.drain(o.emit, o.cursor);
    o.emit({ stepId: resStep, from: to, to: from, label: `${r.status} ${r.ok ? 'OK' : 'error'}`, status: r.ok ? 'ok' : 'error', note: r.ok ? undefined : (b?.error_description || b?.error), response: { status: r.status, statusText: r.statusText, headers: this.pickHeaders(r, ['content-type', 'www-authenticate']), body: b } });
    if (!r.ok) throw new Error(b?.error_description || b?.error || `${path} returned ${r.status}`);
    return b;
  },

  async runObo(o) {
    o.emit({ stepId: 'obo-start', from: 'user', to: 'browser', label: 'Open "My orders"', determinism: 'human' });
    const tc = await this.signIn('obo', o, { scope: `openid profile offline_access ${this.health.scopes.api}` });
    this.guard(o);
    await this.callServer(o, { reqStep: 'obo-call-req', resStep: 'obo-call-res', from: 'browser', to: 'api', labelReq: 'GET /api/obo/me (Bearer Tc)', method: 'GET', path: '/api/obo/me', token: tc, tokLabel: 'Tc: user token for the middle-tier API' });
  },

  async runAgentObo(o) {
    o.emit({ stepId: 'ao-ask', from: 'user', to: 'browser', label: '"What\'s my job title?"', determinism: 'human' });
    const tc = await this.signIn('ao', o, { scope: `openid profile offline_access ${this.health.scopes.blueprint}` });
    this.guard(o);
    await this.callServer(o, { reqStep: 'ao-call-req', resStep: 'ao-call-res', from: 'browser', to: 'agent', labelReq: 'POST /api/agent/obo (Bearer Tc)', method: 'POST', path: '/api/agent/obo', token: tc, tokLabel: 'Tc: user token for the blueprint', body: { prompt: 'What\'s my job title?' } });
  },

  /* ---------- MCP client implemented in the browser ---------- */
  async mcpPost(o, { reqStep, resStep, labelReq, rpc, token, session }) {
    const headers = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25', 'X-Run-Id': o.runId };
    if (token) headers.Authorization = `Bearer ${token}`;
    if (session) headers['Mcp-Session-Id'] = session;
    o.emit({ stepId: reqStep, from: 'mcpclient', to: 'mcpserver', label: labelReq, request: { method: 'POST', url: `${location.origin}/mcp`, headers: { ...headers, ...(token ? { Authorization: `Bearer ${maskToken(token)}` } : {}) }, body: rpc }, tokens: token ? [this.bearerTok(token, 'Tmcp: token for the MCP server')] : [] });
    const r = await fetch('/mcp', { method: 'POST', headers, body: JSON.stringify(rpc) });
    const b = r.status === 202 ? '' : await this.readBody(r);
    if (token) await this.drain(o.emit, o.cursor);
    if (resStep) o.emit({ stepId: resStep, from: 'mcpserver', to: 'mcpclient', label: `${r.status} ${rpc.method}`, status: r.ok || r.status === 401 ? 'ok' : 'error', response: { status: r.status, statusText: r.statusText, headers: this.pickHeaders(r, ['content-type', 'www-authenticate', 'mcp-session-id']), body: b } });
    return { r, b };
  },
  async runMcpAuth(o) {
    const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'authflow-demonstrator', version: '1.0' } } };
    o.emit({ stepId: 'ma-connect', from: 'user', to: 'mcpclient', label: 'Add server / start session', determinism: 'human' });
    const first = await this.mcpPost(o, { reqStep: 'ma-init-req', resStep: 'ma-401', labelReq: 'POST /mcp initialize (no token)', rpc: init });
    const wa = first.r.headers.get('www-authenticate') || '';
    const prmUrl = (wa.match(/resource_metadata="([^"]+)"/) || [])[1];
    if (first.r.status !== 401 || !prmUrl) throw new Error('Expected a 401 challenge with resource_metadata');
    o.emit({ stepId: 'ma-prm-req', from: 'mcpclient', to: 'mcpserver', label: 'GET /.well-known/oauth-protected-resource', request: { method: 'GET', url: prmUrl, headers: {} } });
    const pr = await fetch(new URL(prmUrl).pathname); const prm = await pr.json();
    o.emit({ stepId: 'ma-prm-res', from: 'mcpserver', to: 'mcpclient', label: 'PRM JSON', response: { status: pr.status, statusText: pr.statusText, headers: { 'content-type': pr.headers.get('content-type') }, body: prm } });
    const as = prm.authorization_servers[0];
    const asmUrl = `${as.replace(/\/$/, '')}/.well-known/openid-configuration`;
    o.emit({ stepId: 'ma-asm-req', from: 'mcpclient', to: 'entra', label: 'GET /.well-known/openid-configuration', request: { method: 'GET', url: asmUrl, headers: {} } });
    const ar = await fetch(asmUrl); const asm = await ar.json();
    const short = { issuer: asm.issuer, authorization_endpoint: asm.authorization_endpoint, token_endpoint: asm.token_endpoint, jwks_uri: asm.jwks_uri, response_types_supported: asm.response_types_supported, code_challenge_methods_supported: asm.code_challenge_methods_supported ?? '(not advertised)', grant_types_supported: asm.grant_types_supported ?? '(not advertised)' };
    o.emit({ stepId: 'ma-asm-res', from: 'entra', to: 'mcpclient', label: 'AS metadata', response: { status: ar.status, statusText: ar.statusText, headers: { 'content-type': ar.headers.get('content-type') }, body: short },
      checks: [{ name: 'issuer equals the authorization_servers entry', ok: asm.issuer === as, detail: asm.issuer }, { name: 'code_challenge_methods_supported advertised (S256)', ok: Array.isArray(asm.code_challenge_methods_supported) ? asm.code_challenge_methods_supported.includes('S256') : false, detail: Array.isArray(asm.code_challenge_methods_supported) ? asm.code_challenge_methods_supported.join(', ') : 'Not present in the Entra discovery document. Strict 2025-11-25 clients would refuse, so hosts pre-configure Entra.' }] });
    o.emit({ stepId: 'ma-reg', from: 'mcpclient', to: 'mcpclient', label: 'Choose client_id', data: { client_id: this.health.spaClientId, method: 'Pre-registered Entra app registration. Entra has no DCR or CIMD' } });
    const scope = `openid profile offline_access ${(prm.scopes_supported || [this.health.scopes.mcp]).join(' ')}`;
    const tok = await this.signIn('ma', o, { scope, client: 'mcpclient' });
    this.guard(o);
    const ok = await this.mcpPost(o, { reqStep: 'ma-init2-req', resStep: 'ma-init2-res', labelReq: 'POST /mcp initialize (Bearer Tmcp)', rpc: init, token: tok });
    if (!ok.r.ok) throw new Error('initialize failed');
    const session = ok.r.headers.get('mcp-session-id');
    await this.mcpPost(o, { reqStep: 'ma-initialized', resStep: null, labelReq: 'notifications/initialized', rpc: { jsonrpc: '2.0', method: 'notifications/initialized' }, token: tok, session });
    await this.mcpPost(o, { reqStep: 'ma-list-req', resStep: 'ma-list-res', labelReq: 'tools/list', rpc: { jsonrpc: '2.0', id: 2, method: 'tools/list' }, token: tok, session });
    this.mcpSession = { token: tok, session };
  },
  /* ---------- access, MFA and devices ---------- */
  waitForClick(o, html) {
    return new Promise((resolve, reject) => {
      o.banner(html);
      const btn = document.getElementById('liveContinue');
      const iv = setInterval(() => { if (this.aborted || o.runId !== this.runId) { clearInterval(iv); reject(new Error('Run was reset')); } }, 500);
      btn.onclick = () => { clearInterval(iv); const popup = this.openPopup(); o.banner(''); resolve(popup); };
    });
  },
  async runStepUp(o) {
    const h = this.health, scope = `openid profile offline_access ${h.scopes.api}`, ctxId = h.stepUpAuthContext || 'c1';
    o.emit({ stepId: 'su-start', from: 'user', to: 'browser', label: 'Approve PO-10442', determinism: 'human' });
    const call = async (tok, reqStep, resStep) => {
      const body = { paymentId: 'PO-10442', amount: 12400 };
      const headers = { Authorization: `Bearer ${tok}`, 'X-Run-Id': o.runId, 'Content-Type': 'application/json' };
      o.emit({ stepId: reqStep, from: 'browser', to: 'api', label: 'POST /api/stepup/approve', request: { method: 'POST', url: `${location.origin}/api/stepup/approve`, headers: { ...headers, Authorization: `Bearer ${maskToken(tok)}` }, body }, tokens: [this.bearerTok(tok, 'User token for the API')] });
      const r = await fetch('/api/stepup/approve', { method: 'POST', headers, body: JSON.stringify(body) });
      const b = await this.readBody(r);
      await this.drain(o.emit, o.cursor);
      if (!(r.status === 401 && b?.error === 'insufficient_claims')) {
        o.emit({ stepId: resStep, from: 'api', to: 'browser', label: `${r.status} ${r.ok ? 'approved' : 'error'}`, status: r.ok ? 'ok' : 'error', note: r.ok ? undefined : (b?.error_description || b?.error), response: { status: r.status, statusText: r.statusText, headers: this.pickHeaders(r, ['content-type', 'www-authenticate']), body: b } });
      }
      return { r, b };
    };
    const tc = await this.signIn('su', o, { scope });
    this.guard(o);
    const first = await call(tc, 'su-call-req', 'su-call-res');
    if (first.r.ok) { o.emit({ stepId: 'su-note', from: 'api', to: 'api', label: 'Already satisfied', note: `The first token already carried ${ctxId}, so no challenge was needed.` }); return; }
    if (first.r.status !== 401 || first.b?.error !== 'insufficient_claims') throw new Error(first.b?.error_description || `Unexpected ${first.r.status}`);
    const claims = first.b.claims || JSON.stringify({ access_token: { acrs: { essential: true, value: ctxId } } });
    const popup = await this.waitForClick(o, `<div class="notice info" style="display:flex;gap:12px;align-items:center;flex-wrap:wrap"><span><b>Step-up needed.</b> The API asked for authentication context ${esc(ctxId)}. Continue to sign in again with the claims.</span><button class="btn primary sm" id="liveContinue">Continue with step-up</button></div>`);
    const tc2 = await this.signIn('su2', { ...o, popup }, { scope, extraQuery: { claims } });
    this.guard(o);
    await call(tc2, 'su-call2-req', 'su-approve-res');
  },
  async runMethods(o) {
    const PR = { fido2AuthenticationMethod: ['Passkey or FIDO2 key', true], windowsHelloForBusinessAuthenticationMethod: ['Windows Hello for Business', true], platformCredentialAuthenticationMethod: ['Platform SSO on macOS', true], x509CertificateAuthenticationMethod: ['Certificate', true],
      microsoftAuthenticatorAuthenticationMethod: ['Microsoft Authenticator', false], phoneAuthenticationMethod: ['Phone, SMS or voice', false], softwareOathAuthenticationMethod: ['Software OTP', false], hardwareOathAuthenticationMethod: ['Hardware OTP', false],
      emailAuthenticationMethod: ['Email, for password reset', false], passwordAuthenticationMethod: ['Password', false], temporaryAccessPassAuthenticationMethod: ['Temporary Access Pass', false] };
    const at = await this.signIn('pl', o, { scope: this.health.scopes.methods });
    this.guard(o);
    const amr = decodeJwt(at)?.payload?.amr || [];
    o.emit({ stepId: 'pl-amr', from: 'browser', to: 'browser', label: 'Read amr from the token', data: { amr: amr.join(', ') || 'none' }, tokens: [this.bearerTok(at, 'Your access token for Graph')], note: 'amr lists the methods Entra used for this sign-in.' });
    const url = 'https://graph.microsoft.com/v1.0/me/authentication/methods';
    o.emit({ stepId: 'pl-methods-req', from: 'browser', to: 'graph', label: 'GET /me/authentication/methods', request: { method: 'GET', url, headers: { Authorization: `Bearer ${maskToken(at)}` } } });
    const r = await fetch(url, { headers: { Authorization: `Bearer ${at}` } });
    const b = await this.readBody(r);
    const list = (b?.value || []).map((m) => (m['@odata.type'] || '').replace('#microsoft.graph.', ''));
    o.emit({ stepId: 'pl-methods-res', from: 'graph', to: 'browser', label: `${r.status} methods`, status: r.ok ? 'ok' : 'error', note: r.ok ? undefined : (b?.error?.message || 'Needs the UserAuthenticationMethod.Read scope'), response: { status: r.status, statusText: r.statusText, headers: { 'content-type': r.headers.get('content-type') || '' }, body: { value: list.map((t) => ({ '@odata.type': t })) } } });
    if (!r.ok) throw new Error(b?.error?.message || `Graph returned ${r.status}`);
    const checks = list.map((t) => ({ name: (PR[t] || [t])[0], ok: !!(PR[t] || [])[1], detail: (PR[t] || [])[1] ? 'Phishing-resistant' : 'Can be relayed by a phishing proxy' }));
    const strong = checks.some((x) => x.ok);
    checks.unshift({ name: 'At least one phishing-resistant method registered', ok: strong });
    o.emit({ stepId: 'pl-assess', from: 'browser', to: 'browser', label: strong ? 'Phishing-resistant method found' : 'Only phishable methods', determinism: 'protocol', status: strong ? 'ok' : 'error', checks, note: strong ? 'Now make Conditional Access require it with an authentication strength.' : 'Register a passkey, then require it with an authentication strength.' });
  },
  async runDevice(o) {
    const at = await this.signIn('dv', o, { scope: this.health.scopes.graph });
    this.guard(o);
    const p = decodeJwt(at)?.payload || {};
    o.emit({ stepId: 'dv-inspect', from: 'browser', to: 'browser', label: p.deviceid ? 'deviceid present' : 'No deviceid', determinism: 'protocol', tokens: [this.bearerTok(at, 'Your access token for Graph')],
      data: { deviceid: p.deviceid || 'none', amr: (p.amr || []).join(', ') || 'none' },
      checks: [{ name: 'Browser presented a device identity', ok: !!p.deviceid, detail: p.deviceid ? 'This sign-in came from a registered or joined device' : 'Unknown device, or a browser without the PRT extension' }, { name: 'amr values', ok: null, detail: (p.amr || []).join(', ') || 'none' }],
      note: p.deviceid ? 'Conditional Access could require this device to be compliant.' : 'Conditional Access sees this as an unmanaged device.' });
  },

  async runMcpObo(o) {
    o.emit({ stepId: 'mo-ask', from: 'user', to: 'mcpclient', label: '"Who am I in Contoso?"', determinism: 'human' });
    let s = this.mcpSession;
    const exp = s ? decodeJwt(s.token)?.payload?.exp : 0;
    if (!s || exp < nowSec() + 60) {
      if (!o.popup) throw new Error('Run the MCP authorization tab first, or allow popups so this flow can sign in itself.');
      const tok = await this.signIn('ma', o, { scope: `openid profile offline_access ${this.health.scopes.mcp}`, client: 'mcpclient' });
      s = this.mcpSession = { token: tok, session: null };
    } else if (o.popup && !o.popup.closed) o.popup.close();
    o.emit({ stepId: 'mo-plan-req', from: 'mcpclient', to: 'llm', label: 'Prompt + tool catalogue', simulated: true, note: 'The demo server has no model, so this step is simulated.' });
    o.emit({ stepId: 'mo-plan-res', from: 'llm', to: 'mcpclient', label: 'tool_call: whoami', determinism: 'ai', simulated: true });
    const approved = window.confirm('Allow the MCP tool "whoami" to run on your behalf?');
    o.emit({ stepId: 'mo-approve', from: 'mcpclient', to: 'user', label: approved ? 'Approved' : 'Denied', determinism: 'human', status: approved ? 'ok' : 'error', note: approved ? 'The presenter approved the tool call in a real dialog.' : 'The presenter denied the tool call, so no token exchange happens.' });
    if (!approved) return;
    const { r, b } = await this.mcpPost(o, { reqStep: 'mo-call-req', resStep: 'mo-call-res', labelReq: 'tools/call whoami (Bearer Tmcp)', rpc: { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'whoami', arguments: {} } }, token: s.token, session: s.session });
    if (!r.ok || b?.error) throw new Error(b?.error?.message || `tools/call returned ${r.status}`);
    o.emit({ stepId: 'mo-final-req', from: 'mcpclient', to: 'llm', label: 'Tool output', simulated: true });
    o.emit({ stepId: 'mo-final-res', from: 'llm', to: 'mcpclient', label: 'Answer', determinism: 'ai', simulated: true });
    let who = ''; try { who = JSON.parse(b.result.content[0].text).displayName; } catch { /* ignore */ }
    o.emit({ stepId: 'mo-show', from: 'mcpclient', to: 'user', label: `"You are ${who || 'signed in'}"` });
  },
};
