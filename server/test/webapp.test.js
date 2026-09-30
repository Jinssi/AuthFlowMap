// Confidential-client web app flow (/webapp/*) with mocked Entra/Graph and a local JWKS.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createApp } from '../src/server.js';
import { buildConfig } from '../src/config.js';
import { listen, fakeJwt, jsonResponse, selfSignedCert, TEST_ENV, TENANT } from './helpers.js';

const WA_SECRET = 'WEBAPP-SECRET-value-123456';
const REFRESH = '1.AXoA-webapp-refresh-token';
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'authflow-wa-'));
const cert = selfSignedCert('authflow-webapp-test');
fs.writeFileSync(path.join(tmpDir, 'webapp.pem'), cert.certPem);
fs.writeFileSync(path.join(tmpDir, 'webapp.key'), cert.keyPem);
const X5T = crypto.createHash('sha1').update(cert.certDer).digest('base64url');

const ENV = {
  ...TEST_ENV,
  WEBAPP_CLIENT_ID: 'webapp-client-id',
  WEBAPP_CLIENT_SECRET: WA_SECRET,
  WEBAPP_CERT_PATH: path.join(tmpDir, 'webapp.pem'),
  WEBAPP_KEY_PATH: path.join(tmpDir, 'webapp.key'),
};
const cfg = buildConfig(ENV);

const STEPS_LOGIN = ['wa-req', 'wa-pkce', 'wa-redirect', 'wa-authz'];
const STEPS_CALLBACK = [
  'wa-code', 'wa-callback', 'wa-state', 'wa-token-req', 'wa-token-res', 'wa-idtoken', 'wa-session',
  'wa-graph-req', 'wa-graph-res', 'wa-page',
];

let privateKey;
let app;
let srv;
const calls = [];
const sensitive = []; // raw values that must never appear in a trace
const current = { challenge: null, nonce: null, idNonce: null };

async function idToken(nonce) {
  const raw = await new SignJWT({ tid: TENANT, name: 'Ada', preferred_username: 'ada@contoso.test', nonce })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'JWT' })
    .setIssuer(cfg.issuerV2).setAudience('webapp-client-id').setIssuedAt().setExpirationTime('10m')
    .sign(privateKey);
  sensitive.push(raw, raw.split('.')[2]);
  return raw;
}

async function mockFetch(url, init = {}) {
  const u = String(url);
  const form = init.body ? Object.fromEntries(new URLSearchParams(init.body)) : null;
  calls.push({ url: u, method: init.method, form, headers: init.headers });
  if (u === cfg.tokenEndpoint && form?.grant_type === 'authorization_code') {
    if (form.client_assertion) sensitive.push(form.client_assertion, form.client_assertion.split('.')[2]);
    const s256 = crypto.createHash('sha256').update(form.code_verifier ?? '').digest('base64url');
    if (s256 !== current.challenge) {
      return jsonResponse(400, { error: 'invalid_grant', error_description: 'AADSTS501481: The Code_Verifier does not match the code_challenge.' });
    }
    const access = fakeJwt({ aud: '00000003-0000-0000-c000-000000000000', scp: 'User.Read' });
    sensitive.push(access.raw, access.signature);
    return jsonResponse(200, {
      token_type: 'Bearer', expires_in: 3599, scope: 'openid profile offline_access User.Read',
      access_token: access.raw, id_token: await idToken(current.idNonce ?? current.nonce), refresh_token: REFRESH,
    });
  }
  if (u.startsWith('https://graph.microsoft.com/v1.0/me')) {
    return jsonResponse(200, { id: 'u1', displayName: 'Ada <Lovelace>', userPrincipalName: 'ada@contoso.test' });
  }
  return jsonResponse(404, { error: { code: 'NotFound', message: 'no mock' } });
}

test.before(async () => {
  const kp = await generateKeyPair('RS256');
  privateKey = kp.privateKey;
  const jwk = { ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  app = createApp({ cfg, fetchImpl: mockFetch, jwks: createLocalJWKSet({ keys: [jwk] }), log: () => {} });
  srv = await listen(app);
});
test.after(async () => {
  await srv.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

const trace = () => app.locals.ctx.trace;

function setCookies(res) {
  return res.headers.getSetCookie();
}

async function login(runId, variant = 'secret') {
  const res = await fetch(`${srv.base}/webapp/login?runId=${runId}&variant=${variant}`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  const location = new URL(res.headers.get('location'));
  const bind = setCookies(res).find((c) => c.startsWith('wa_bind='));
  const cookie = bind.split(';')[0];
  current.challenge = location.searchParams.get('code_challenge');
  current.nonce = location.searchParams.get('nonce');
  current.idNonce = null;
  const state = location.searchParams.get('state');
  const entry = app.locals.webApp.pending.get(state);
  sensitive.push(entry.verifier, entry.bindingId);
  return { res, location, cookie, bind, state };
}

function callback(query, cookie) {
  return fetch(`${srv.base}/webapp/callback?${query}`, { headers: cookie ? { cookie } : {}, redirect: 'manual' });
}

function newCode() {
  const code = `M.C5_BAY.2.U.fake-auth-code-${crypto.randomBytes(12).toString('hex')}`;
  sensitive.push(code);
  return code;
}

function assertNoLeaks(obj) {
  const s = JSON.stringify(obj);
  for (const v of sensitive) assert.ok(!s.includes(v), `sensitive value leaked: ${v.slice(0, 12)}`);
  assert.ok(!s.includes(WA_SECRET), 'client secret leaked');
  assert.ok(!s.includes('webapp-refresh-token'), 'refresh token leaked');
  assert.ok(!s.includes('fake-auth-code'), 'authorization code leaked');
  for (const e of obj.events) for (const k of ['from', 'to', 'label', 'determinism']) assert.ok(k in e, `${e.stepId}.${k}`);
}

test('login: 302 to /authorize with all params, wa_bind cookie, traced', async () => {
  const { location, bind, state } = await login('wa-login-0001');
  assert.equal(`${location.origin}${location.pathname}`, `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/authorize`);
  const p = Object.fromEntries(location.searchParams);
  assert.equal(p.client_id, 'webapp-client-id');
  assert.equal(p.response_type, 'code');
  assert.equal(p.redirect_uri, 'http://localhost:5100/webapp/callback');
  assert.equal(p.response_mode, 'query');
  assert.equal(p.scope, 'openid profile offline_access User.Read');
  assert.equal(p.code_challenge_method, 'S256');
  assert.equal(p.prompt, 'select_account');
  assert.match(p.state, /^[A-Za-z0-9_-]{43}$/);
  assert.match(p.nonce, /^[0-9a-f-]{36}$/);
  assert.match(p.code_challenge, /^[A-Za-z0-9_-]{43}$/);
  const entry = app.locals.webApp.pending.get(state);
  assert.ok(entry.verifier.length >= 43 && entry.verifier.length <= 128);
  assert.equal(crypto.createHash('sha256').update(entry.verifier).digest('base64url'), p.code_challenge);
  assert.match(bind, /^wa_bind=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Lax; Path=\/webapp; Max-Age=600$/);

  const t = trace().get('wa-login-0001');
  assert.equal(t.done, false, 'login must not end the run');
  assert.equal(t.error, null);
  const polled = await (await fetch(`${srv.base}/api/trace/wa-login-0001`)).json();
  assert.equal(polled.done, false);
  assert.equal(polled.events.length, STEPS_LOGIN.length);
  assert.deepEqual(t.events.map((e) => e.stepId), STEPS_LOGIN);
  const [req, pkce, redirect, authz] = t.events;
  assert.deepEqual([req.from, req.to, req.request.method], ['browser', 'webapp', 'GET']);
  assert.deepEqual(pkce.data, {
    state: `${state.slice(0, 8)}…`, nonce: p.nonce, code_challenge: p.code_challenge, method: 'S256', code_verifier: 'kept on the server',
  });
  assert.equal(redirect.response.status, 302);
  assert.equal(redirect.response.headers.location, location.href);
  assert.equal(redirect.response.headers['set-cookie'], 'wa_bind=…[masked]; HttpOnly; SameSite=Lax');
  assert.deepEqual([authz.from, authz.to, authz.request.method, authz.request.url], ['browser', 'entra', 'GET', location.href]);
  assertNoLeaks(t);
});

test('login: 400 on bad variant or runId, 503 when the variant is not configured', async () => {
  let res = await fetch(`${srv.base}/webapp/login?runId=wa-login-0002&variant=password`, { redirect: 'manual' });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_request');
  res = await fetch(`${srv.base}/webapp/login?runId=bad&variant=secret`, { redirect: 'manual' });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'invalid_run_id');

  const secretOnly = createApp({ cfg: buildConfig({ ...ENV, WEBAPP_CERT_PATH: '', WEBAPP_KEY_PATH: '' }), fetchImpl: mockFetch, log: () => {} });
  const s = await listen(secretOnly);
  try {
    res = await fetch(`${s.base}/webapp/login?runId=wa-login-0003&variant=certificate`, { redirect: 'manual' });
    assert.equal(res.status, 503);
    assert.equal((await res.json()).error, 'not_configured');
    assert.equal(setCookies(res).length, 0);
    res = await fetch(`${s.base}/webapp/login?runId=wa-login-0003&variant=secret`, { redirect: 'manual' });
    assert.equal(res.status, 302);
  } finally {
    await s.close();
  }
});

for (const variant of ['secret', 'certificate']) {
  test(`callback happy path (${variant}): code redeemed on the server, ID token validated, session cookie only`, async () => {
    const runId = `wa-happy-${variant}`;
    const { state, cookie } = await login(runId, variant);
    const code = newCode();
    const afterLogin = await (await fetch(`${srv.base}/api/trace/${runId}`)).json();
    assert.deepEqual([afterLogin.done, afterLogin.error], [false, null], 'run stays open after login');
    calls.length = 0;
    const res = await callback(`code=${encodeURIComponent(code)}&state=${state}`, cookie);
    assert.equal(res.status, 200);
    const afterCallback = await (await fetch(`${srv.base}/api/trace/${runId}`)).json();
    assert.deepEqual([afterCallback.done, afterCallback.error], [true, null], 'callback ends the run');
    const html = await res.text();
    assert.match(html, /Signed in to the demo web app as Ada &lt;Lovelace&gt;\. The tokens stayed on the server\./);
    const csp = res.headers.get('content-security-policy');
    const nonce = /script-src 'nonce-([^']+)'/.exec(csp)[1];
    assert.ok(html.includes(`<script nonce="${nonce}">`));
    assert.match(csp, /default-src 'none'/);
    assert.ok(html.includes(`postMessage({ type: 'authflow-webapp-done', runId: "${runId}" }, location.origin)`));
    assert.ok(html.includes('setTimeout(window.close, 2500)'));
    assert.ok(!/src=|href=/.test(html), 'no external resources');
    const cookies = setCookies(res);
    const session = cookies.find((c) => c.startsWith('wa_session='));
    assert.match(session, /^wa_session=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Lax; Path=\/webapp; Max-Age=1800$/);
    assert.ok(cookies.some((c) => /^wa_bind=; .*Max-Age=0$/.test(c)), 'wa_bind cleared');
    for (const v of [code, WA_SECRET, REFRESH]) assert.ok(!html.includes(v));

    // Tokens are in the server-side session.
    const sid = session.split(';')[0].slice('wa_session='.length);
    sensitive.push(sid);
    const stored = app.locals.webApp.sessions.get(sid);
    assert.equal(stored.tokens.refresh_token, REFRESH);
    assert.equal(stored.name, 'Ada <Lovelace>');

    // What was sent to Entra.
    const sent = calls.find((c) => c.form?.grant_type === 'authorization_code').form;
    assert.equal(sent.client_id, 'webapp-client-id');
    assert.equal(sent.code, code);
    assert.equal(sent.redirect_uri, 'http://localhost:5100/webapp/callback');
    assert.equal(sent.scope, 'openid profile offline_access User.Read');
    assert.equal(crypto.createHash('sha256').update(sent.code_verifier).digest('base64url'), current.challenge);
    if (variant === 'secret') {
      assert.equal(sent.client_secret, WA_SECRET);
      assert.equal(sent.client_assertion, undefined);
      assert.equal(sent.client_assertion_type, undefined);
    } else {
      assert.equal(sent.client_secret, undefined);
      assert.equal(sent.client_assertion_type, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
      const [h, pl, sig] = sent.client_assertion.split('.');
      const header = JSON.parse(Buffer.from(h, 'base64url'));
      const payload = JSON.parse(Buffer.from(pl, 'base64url'));
      assert.deepEqual(header, { alg: 'RS256', typ: 'JWT', x5t: X5T });
      assert.equal(payload.aud, cfg.tokenEndpoint);
      assert.equal(payload.iss, 'webapp-client-id');
      assert.equal(payload.sub, 'webapp-client-id');
      assert.ok(crypto.verify('sha256', Buffer.from(`${h}.${pl}`), cert.publicKey, Buffer.from(sig, 'base64url')));
    }
    const graph = calls.find((c) => c.url.startsWith('https://graph.microsoft.com'));
    assert.equal(graph.url, 'https://graph.microsoft.com/v1.0/me?$select=displayName,userPrincipalName,id');

    // Trace.
    const t = trace().get(runId);
    assert.equal(t.done, true);
    assert.equal(t.error, null);
    assert.deepEqual(t.events.map((e) => e.stepId), [...STEPS_LOGIN, ...STEPS_CALLBACK]);
    const ev = Object.fromEntries(t.events.map((e) => [e.stepId, e]));
    assert.equal(ev['wa-code'].response.headers.location, `http://localhost:5100/webapp/callback?code=${code.slice(0, 6)}…[redacted]&state=${state}`);
    assert.deepEqual([ev['wa-code'].from, ev['wa-code'].to], ['entra', 'browser']);
    assert.equal(ev['wa-callback'].request.url, ev['wa-code'].response.headers.location);
    assert.ok(ev['wa-state'].checks.every((c) => c.ok));
    assert.deepEqual(ev['wa-state'].checks.map((c) => c.name), ['State found and unused', 'wa_bind cookie matches', 'Not expired']);
    assert.deepEqual([ev['wa-token-req'].from, ev['wa-token-req'].to, ev['wa-token-res'].from, ev['wa-token-res'].to], ['webapp', 'entra', 'entra', 'webapp']);
    const body = ev['wa-token-req'].request.body;
    assert.equal(body.code, code.slice(0, 6) + '…');
    assert.equal(body.code_verifier.length, 7);
    if (variant === 'secret') {
      assert.equal(body.client_secret, '••••••••[redacted]');
      assert.equal(body.client_assertion, undefined);
    } else {
      assert.equal(body.client_secret, undefined);
      assert.match(body.client_assertion, /\[signature redacted\]$/);
      assert.equal(ev['wa-token-req'].tokens[0].header.x5t, X5T);
    }
    assert.deepEqual(ev['wa-token-res'].checks, [
      { name: `App authenticated with ${variant === 'secret' ? 'its client secret' : 'a certificate-signed assertion'}`, ok: true },
      { name: 'PKCE verifier matched the challenge', ok: true },
      { name: 'Code bound to this client_id and redirect_uri', ok: true },
    ]);
    assert.equal(ev['wa-token-res'].response.body.refresh_token, '1.AXoA…[redacted]');
    assert.equal(ev['wa-idtoken'].status, 'ok');
    assert.deepEqual(ev['wa-idtoken'].checks.map((c) => c.ok), [true, true, true, true, true]);
    assert.equal(ev['wa-idtoken'].tokens[0].label, 'id_token');
    assert.equal(ev['wa-idtoken'].tokens[0].payload.nonce, current.nonce);
    assert.deepEqual(ev['wa-session'].response.headers, { 'set-cookie': 'wa_session=…[masked]; HttpOnly; SameSite=Lax; Path=/webapp' });
    assert.equal(ev['wa-session'].note, 'The browser gets a session cookie. The tokens stay in the server\'s token cache.');
    assert.deepEqual([ev['wa-graph-req'].from, ev['wa-graph-req'].to], ['webapp', 'graph']);
    assert.deepEqual(ev['wa-page'].response, { status: 200, statusText: 'OK', headers: { 'content-type': 'text/html' }, body: 'Hello Ada <Lovelace>' });
    assertNoLeaks(t);
  });
}

test('callback: unknown state and reused state -> 400', async () => {
  let res = await callback(`code=abc&state=${crypto.randomBytes(32).toString('base64url')}`);
  assert.equal(res.status, 400);
  assert.match(res.headers.get('content-type'), /^text\/html/);
  assert.match(await res.text(), /unknown, expired or already used/);

  const { state, cookie } = await login('wa-reuse-0001');
  res = await callback(`code=${newCode()}&state=${state}`, cookie);
  assert.equal(res.status, 200);
  const before = trace().get('wa-reuse-0001').events.length;
  res = await callback(`code=${newCode()}&state=${state}`, cookie);
  assert.equal(res.status, 400);
  assert.equal(trace().get('wa-reuse-0001').events.length, before, 'no events written for a used state');
});

test('callback: missing or mismatched wa_bind cookie fails wa-state, run error, no token request', async () => {
  for (const [runId, cookie] of [['wa-bind-0001', null], ['wa-bind-0002', 'wa_bind=someone-elses-binding-cookie']]) {
    const { state } = await login(runId);
    calls.length = 0;
    const res = await callback(`code=${newCode()}&state=${state}`, cookie);
    assert.equal(res.status, 400);
    assert.equal(setCookies(res).length, 0);
    const t = trace().get(runId);
    assert.deepEqual(t.events.map((e) => e.stepId), [...STEPS_LOGIN, 'wa-code', 'wa-callback', 'wa-state']);
    const st = t.events.at(-1);
    assert.equal(st.status, 'error');
    assert.equal(st.checks.find((c) => c.name === 'wa_bind cookie matches').ok, false);
    assert.equal(t.done, true);
    assert.match(t.error, /wa_bind cookie matches/);
    assert.equal(calls.length, 0);
    assert.equal(app.locals.webApp.pending.has(state), false, 'state is single use even on failure');
    assertNoLeaks(t);
  }
});

test('callback: expired pending state fails the expiry check', async () => {
  const { state, cookie } = await login('wa-expired-01');
  app.locals.webApp.pending.get(state).createdAt -= 11 * 60 * 1000;
  const res = await callback(`code=${newCode()}&state=${state}`, cookie);
  assert.equal(res.status, 400);
  const t = trace().get('wa-expired-01');
  assert.equal(t.events.at(-1).checks.find((c) => c.name === 'Not expired').ok, false);
  assert.match(t.error, /Not expired/);
});

test('callback: Entra error -> error event, HTML error page, run error', async () => {
  const { state, cookie } = await login('wa-entraerr-1');
  const res = await callback(`error=access_denied&error_description=${encodeURIComponent('AADSTS65004: User declined <consent>')}&state=${state}`, cookie);
  assert.equal(res.status, 400);
  const html = await res.text();
  assert.match(html, /access_denied: AADSTS65004: User declined &lt;consent&gt;/);
  const t = trace().get('wa-entraerr-1');
  assert.deepEqual(t.events.map((e) => e.stepId), [...STEPS_LOGIN, 'wa-code', 'wa-callback', 'wa-state']);
  assert.equal(t.events[4].status, 'error');
  assert.equal(t.error, 'access_denied: AADSTS65004: User declined <consent>');
});

test('callback: nonce mismatch in the ID token fails wa-idtoken, no session', async () => {
  const { state, cookie } = await login('wa-nonce-0001');
  current.idNonce = crypto.randomUUID();
  const sessionsBefore = app.locals.webApp.sessions.size;
  const res = await callback(`code=${newCode()}&state=${state}`, cookie);
  assert.equal(res.status, 400);
  assert.ok(!setCookies(res).some((c) => c.startsWith('wa_session=')));
  assert.equal(app.locals.webApp.sessions.size, sessionsBefore);
  const t = trace().get('wa-nonce-0001');
  assert.deepEqual(t.events.map((e) => e.stepId), [...STEPS_LOGIN, 'wa-code', 'wa-callback', 'wa-state', 'wa-token-req', 'wa-token-res', 'wa-idtoken']);
  const idt = t.events.at(-1);
  assert.equal(idt.status, 'error');
  assert.deepEqual(idt.checks.filter((c) => !c.ok).map((c) => c.name), ['Nonce']);
  assert.equal(t.error, 'Nonce check failed');
  assertNoLeaks(t);
});

test('callback: PKCE rejected by Entra -> wa-token-res error with the PKCE check marked', async () => {
  const { state, cookie } = await login('wa-pkce-00001');
  current.challenge = 'not-the-challenge';
  const res = await callback(`code=${newCode()}&state=${state}`, cookie);
  assert.equal(res.status, 502);
  const t = trace().get('wa-pkce-00001');
  const last = t.events.at(-1);
  assert.equal(last.stepId, 'wa-token-res');
  assert.equal(last.status, 'error');
  assert.deepEqual(last.checks.map((c) => c.ok), [true, false, false]);
  assert.match(t.error, /^invalid_grant: AADSTS501481/);
  assertNoLeaks(t);
});

test('health: web-app flags and client id, never secrets or paths', async () => {
  for (const [env, expected] of [
    [ENV, { secret: true, certificate: true }],
    [{ ...ENV, WEBAPP_CLIENT_SECRET: '' }, { secret: false, certificate: true }],
    [{ ...ENV, WEBAPP_KEY_PATH: path.join(tmpDir, 'missing.key') }, { secret: true, certificate: false }],
    [{ ...ENV, TENANT_ID: '' }, { secret: false, certificate: false }],
  ]) {
    const s = await listen(createApp({ cfg: buildConfig(env), log: () => {} }));
    try {
      const j = await (await fetch(`${s.base}/api/health`)).json();
      assert.deepEqual(j.flows['web-app'], expected);
      assert.equal(j.ids.webAppClientId, 'webapp-client-id');
      const str = JSON.stringify(j);
      assert.ok(!str.includes(WA_SECRET));
      assert.ok(!str.includes(tmpDir.replace(/\\/g, '\\\\')) && !str.includes('webapp.pem') && !str.includes('webapp.key'));
    } finally {
      await s.close();
    }
  }
});
