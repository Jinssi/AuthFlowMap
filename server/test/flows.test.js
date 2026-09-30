// End-to-end flow tests with mocked Entra/Graph (fetch) and a local JWKS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createApp } from '../src/server.js';
import { buildConfig } from '../src/config.js';
import { listen, fakeJwt, jsonResponse, waitDone, TEST_ENV, TENANT } from './helpers.js';

const cfg = buildConfig(TEST_ENV);
const SECRETS = Object.entries(TEST_ENV).filter(([k]) => k.endsWith('SECRET')).map(([, v]) => v);
const issued = []; // every raw token the mock handed out or the test created

function mint(payload) {
  const t = fakeJwt(payload);
  issued.push(t);
  return t.raw;
}

// Mock Entra + Graph. Records requests to assert on protocol details.
const calls = [];
let devicePolls = 0;
async function mockFetch(url, init = {}) {
  const u = String(url);
  const form = init.body ? Object.fromEntries(new URLSearchParams(init.body)) : null;
  calls.push({ url: u, method: init.method, form, headers: init.headers });
  if (u.endsWith('/oauth2/v2.0/devicecode')) {
    return jsonResponse(200, {
      device_code: 'DAQABAAEAAAD-secret-device-code', user_code: 'ABCD-EFGH', verification_uri: 'https://microsoft.com/devicelogin',
      expires_in: 900, interval: 5, message: 'To sign in, use a web browser to open https://microsoft.com/devicelogin and enter ABCD-EFGH',
    });
  }
  if (u.endsWith('/oauth2/v2.0/token')) {
    if (form.grant_type === 'urn:ietf:params:oauth:grant-type:device_code') {
      devicePolls += 1;
      if (devicePolls < 7) return jsonResponse(400, { error: 'authorization_pending', error_description: 'AADSTS70016: pending\r\nTrace ID: x' });
      return jsonResponse(200, { token_type: 'Bearer', expires_in: 3599, access_token: mint({ aud: 'graph', scp: 'User.Read' }), id_token: mint({ name: 'Ada' }), refresh_token: '1.AXoA-opaque-refresh-token' });
    }
    if (form.client_id === 'daemon-client-id' && form.client_secret === 'wrong') {
      return jsonResponse(401, { error: 'invalid_client', error_description: 'AADSTS7000215: Invalid client secret provided.' });
    }
    return jsonResponse(200, { token_type: 'Bearer', expires_in: 3599, access_token: mint({ aud: 'x', form_client: form.client_id }) });
  }
  if (u.startsWith('https://graph.microsoft.com/v1.0/users')) return jsonResponse(200, { value: [{ id: 'u1', displayName: 'Ada' }] });
  if (u === 'https://graph.microsoft.com/v1.0/me') return jsonResponse(200, { id: 'u1', displayName: 'Ada Lovelace', userPrincipalName: 'ada@contoso.test' });
  return jsonResponse(404, { error: { code: 'NotFound', message: 'no mock' } });
}

let srv;
let app;
let privateKey;
let jwks;

async function userToken(aud, scp, extra = {}) {
  const raw = await new SignJWT({ scp, tid: TENANT, name: 'Ada', ...extra })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'JWT' })
    .setIssuer(cfg.issuerV2).setAudience(aud).setIssuedAt().setExpirationTime('10m')
    .sign(privateKey);
  issued.push({ raw, signature: raw.split('.')[2] });
  return raw;
}

function assertNoLeaks(obj) {
  const s = JSON.stringify(obj);
  for (const t of issued) {
    assert.ok(!s.includes(t.signature), 'full token signature leaked into trace');
    assert.ok(!s.includes(t.raw), 'full token leaked into trace');
  }
  for (const secret of SECRETS) assert.ok(!s.includes(secret), 'secret leaked into trace');
  assert.ok(!s.includes('secret-device-code'), 'device_code leaked');
  assert.ok(!s.includes('opaque-refresh-token'), 'refresh token leaked');
}

test.before(async () => {
  const kp = await generateKeyPair('RS256');
  privateKey = kp.privateKey;
  const jwk = { ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  jwks = createLocalJWKSet({ keys: [jwk] });
  app = createApp({ cfg, fetchImpl: mockFetch, jwks, sleep: async () => {}, log: () => {} });
  srv = await listen(app);
});
test.after(async () => srv.close());

const trace = () => app.locals.ctx.trace;
const post = (p, body, headers = {}) => fetch(`${srv.base}${p}`, {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
});

test('client-credentials (secret): steps, masking, no leaks', async () => {
  const res = await post('/api/live/client-credentials', { runId: 'cc-run-0001', variant: 'secret' });
  assert.equal(res.status, 202);
  assert.deepEqual(await res.json(), { runId: 'cc-run-0001' });
  const t = await waitDone(trace(), 'cc-run-0001');
  assert.equal(t.error, null);
  assert.deepEqual(t.events.map((e) => e.stepId), ['cc-build-cred', 'cc-token-req', 'cc-token-res', 'cc-graph-req', 'cc-graph-res']);
  const [cred, req, resEvt, greq] = t.events;
  assert.equal(cred.note, 'Loaded the client secret from the server environment. The browser never sees it');
  assert.deepEqual([req.from, req.to, resEvt.from, resEvt.to], ['daemon', 'entra', 'entra', 'daemon']);
  assert.equal(req.request.body.client_secret, '••••••••[redacted]');
  assert.equal(req.request.body.scope, 'https://graph.microsoft.com/.default');
  assert.equal(resEvt.tokens[0].label, 'access_token');
  assert.match(greq.request.url, /\/users\?\$top=1&\$select=id,displayName$/);
  assert.match(greq.request.headers.Authorization, /^Bearer .*\[signature redacted\]$/);
  for (const e of t.events) for (const k of ['seq', 'stepId', 'ts', 'status', 'from', 'to', 'label', 'determinism']) assert.ok(k in e, `${e.stepId}.${k}`);
  // via HTTP too
  const viaHttp = await (await fetch(`${srv.base}/api/trace/cc-run-0001?since=3`)).json();
  assert.equal(viaHttp.events.length, 2);
  assert.equal(viaHttp.done, true);
  assertNoLeaks(t);
});

test('client-credentials Entra error -> error event + run error', async () => {
  const bad = createApp({ cfg: buildConfig({ ...TEST_ENV, DAEMON_CLIENT_SECRET: 'wrong' }), fetchImpl: mockFetch, log: () => {} });
  const s = await listen(bad);
  try {
    await fetch(`${s.base}/api/live/client-credentials`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"runId":"cc-bad-0001"}' });
    const t = await waitDone(bad.locals.ctx.trace, 'cc-bad-0001');
    const last = t.events.at(-1);
    assert.equal(last.stepId, 'cc-token-res');
    assert.equal(last.status, 'error');
    assert.match(last.note, /^invalid_client: AADSTS7000215/);
    assert.match(t.error, /invalid_client/);
  } finally {
    await s.close();
  }
});

test('device code: polls #1 and every 5th are traced, then sign-in, token, /me', async () => {
  devicePolls = 0;
  const res = await post('/api/live/device-code', { runId: 'dc-run-0001' });
  assert.equal(res.status, 202);
  const t = await waitDone(trace(), 'dc-run-0001');
  assert.equal(t.error, null);
  assert.deepEqual(t.events.map((e) => e.stepId), [
    'dc-code-req', 'dc-code-res', 'dc-show-code',
    'dc-poll-req', 'dc-poll-res', // poll 1
    'dc-poll-req', 'dc-poll-res', // poll 5
    'dc-user-signin', 'dc-poll-req', 'dc-token-res',
    'dc-graph-req', 'dc-graph-res',
  ]);
  assert.deepEqual(t.events[1].data, {
    user_code: 'ABCD-EFGH', verification_uri: 'https://microsoft.com/devicelogin', expires_in: 900,
    message: 'To sign in, use a web browser to open https://microsoft.com/devicelogin and enter ABCD-EFGH',
  });
  assert.equal(t.events[2].determinism, 'human');
  assert.equal(t.events[4].status, 'pending');
  assert.equal(t.events[4].note, 'authorization_pending, poll 1');
  assert.equal(t.events[6].note, 'authorization_pending, poll 5');
  assert.equal(t.events[7].note, 'User completed sign-in on a second device');
  assert.equal(t.events[3].request.body.device_code, 'DAQABA…');
  assert.deepEqual(t.events[9].tokens.map((x) => x.label), ['access_token', 'id_token']);
  assertNoLeaks(t);
});

test('agent autonomous: parent token (fmi_path) -> agent token -> graph', async () => {
  const res = await post('/api/live/agent-autonomous', { runId: 'aa-run-0001' });
  assert.equal(res.status, 202);
  const t = await waitDone(trace(), 'aa-run-0001');
  assert.equal(t.error, null);
  assert.deepEqual(t.events.map((e) => e.stepId), ['aa-parent-req', 'aa-parent-res', 'aa-agent-req', 'aa-agent-res', 'aa-graph-req', 'aa-graph-res']);
  const parentReq = t.events[0].request.body;
  assert.deepEqual(parentReq, {
    client_id: 'blueprint-app-id', client_secret: '••••••••[redacted]', grant_type: 'client_credentials',
    scope: 'api://AzureADTokenExchange/.default', fmi_path: 'agent-identity-app-id',
  });
  const agentReq = t.events[2];
  assert.equal(agentReq.request.body.client_assertion_type, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  assert.equal(agentReq.tokens[0].label, 'client_assertion');
  assert.equal(t.events.every((e) => ['agent', 'entra', 'graph'].includes(e.from)), true);
  assertNoLeaks(t);
});

test('OBO: valid user token -> validate, exchange, /me', async () => {
  calls.length = 0;
  const tok = await userToken('api-client-id', 'access_as_user');
  const res = await fetch(`${srv.base}/api/obo/me`, { headers: { authorization: `Bearer ${tok}`, 'x-run-id': 'obo-run-0002' } });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { me: { displayName: 'Ada Lovelace', userPrincipalName: 'ada@contoso.test', id: 'u1' } });
  const t = trace().get('obo-run-0002');
  assert.equal(t.done, true);
  assert.deepEqual(t.events.map((e) => e.stepId), ['obo-validate', 'obo-exchange-req', 'obo-exchange-res', 'obo-graph-req', 'obo-graph-res']);
  assert.ok(t.events[0].checks.every((c) => c.ok));
  assert.equal(t.events[0].checks.length, 6);
  const sent = calls.find((c) => c.form?.requested_token_use === 'on_behalf_of').form;
  assert.equal(sent.assertion, tok);
  assert.equal(sent.client_id, 'api-client-id');
  assert.equal(sent.grant_type, 'urn:ietf:params:oauth:grant-type:jwt-bearer');
  assert.equal(sent.scope, 'https://graph.microsoft.com/User.Read');
  assertNoLeaks(t);
});

test('OBO: wrong audience / missing scope / expired -> 401 with failing check marked', async () => {
  const cases = [
    [await userToken('someone-else', 'access_as_user'), 'Audience'],
    [await userToken('api-client-id', 'User.Read'), 'Scope scp contains access_as_user'],
    [await userToken('api-client-id', 'access_as_user', { tid: 'other-tenant' }), 'Tenant (tid)'],
  ];
  for (const [tok, failing] of cases) {
    const res = await fetch(`${srv.base}/api/obo/me`, { headers: { authorization: `Bearer ${tok}` } });
    assert.equal(res.status, 401);
    const j = await res.json();
    assert.equal(j.checks.find((c) => c.name === failing).ok, false, failing);
    assert.equal(j.checks.filter((c) => !c.ok).length, 1, failing);
  }
  // forged signature
  const forged = fakeJwt({ aud: 'api-client-id', iss: cfg.issuerV2, tid: TENANT, scp: 'access_as_user', exp: Math.floor(Date.now() / 1000) + 600 }, { alg: 'RS256', kid: 'k1' });
  const res = await fetch(`${srv.base}/api/obo/me`, { headers: { authorization: `Bearer ${forged.raw}` } });
  const j = await res.json();
  assert.equal(res.status, 401);
  assert.equal(j.checks[0].ok, false);
  assert.match(j.checks[0].name, /^Signature \(JWKS kid k1\)$/);
});

test('agent OBO: validate, parent, agent OBO, /me, answer', async () => {
  calls.length = 0;
  const tok = await userToken('blueprint-app-id', 'access_as_user');
  const res = await post('/api/agent/obo', { prompt: 'Who am I?' }, { authorization: `Bearer ${tok}`, 'x-run-id': 'ao-run-0001' });
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.equal(j.answer, 'Hi Ada Lovelace, I (agent identity agent-identity-app-id) read your profile on your behalf.');
  const t = trace().get('ao-run-0001');
  assert.deepEqual(t.events.map((e) => e.stepId), ['ao-validate', 'ao-parent-req', 'ao-parent-res', 'ao-obo-req', 'ao-obo-res', 'ao-graph-req', 'ao-graph-res']);
  const sent = calls.find((c) => c.form?.requested_token_use === 'on_behalf_of').form;
  assert.equal(sent.client_id, 'agent-identity-app-id');
  assert.equal(sent.assertion, tok);
  assert.equal(sent.client_assertion_type, 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
  assert.equal(sent.scope, 'https://graph.microsoft.com/.default');
  assertNoLeaks(t);
});

test('MCP: initialize, initialized, tools/list, tools/call whoami (own OBO, token not forwarded)', async () => {
  calls.length = 0;
  const tok = await userToken('api://mcp-client-id', 'mcp.tools');
  const h = { authorization: `Bearer ${tok}`, 'x-run-id': 'mcp-run-0001', accept: 'application/json, text/event-stream' };

  let res = await post('/mcp', { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 't', version: '1' } } }, h);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('mcp-session-id'), /^[0-9a-f-]{36}$/);
  assert.deepEqual((await res.json()).result, { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'authflow-demo-mcp', version: '1.0.0' } });

  res = await post('/mcp', { jsonrpc: '2.0', method: 'notifications/initialized' }, h);
  assert.equal(res.status, 202);

  res = await post('/mcp', { jsonrpc: '2.0', id: 2, method: 'tools/list' }, h);
  assert.equal((await res.json()).result.tools[0].name, 'whoami');

  res = await post('/mcp', { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'whoami', arguments: {} } }, h);
  const call = await res.json();
  assert.deepEqual(JSON.parse(call.result.content[0].text), { displayName: 'Ada Lovelace', userPrincipalName: 'ada@contoso.test' });

  res = await post('/mcp', { jsonrpc: '2.0', id: 4, method: 'resources/list' }, h);
  assert.equal((await res.json()).error.code, -32601);

  // The incoming MCP token is only used as the OBO assertion, never sent to Graph.
  const graphCalls = calls.filter((c) => c.url.startsWith('https://graph.microsoft.com'));
  assert.equal(graphCalls.length, 1);
  assert.notEqual(graphCalls[0].headers.Authorization, `Bearer ${tok}`);
  const obo = calls.find((c) => c.form?.requested_token_use === 'on_behalf_of').form;
  assert.equal(obo.client_id, 'mcp-client-id');
  assert.equal(obo.scope, 'https://graph.microsoft.com/User.Read');

  const t = trace().get('mcp-run-0001');
  assert.deepEqual(
    t.events.map((e) => e.stepId).filter((s) => s !== 'mcp-validate'),
    ['mcp-obo-req', 'mcp-obo-res', 'mcp-graph-req', 'mcp-graph-res'],
  );
  assert.equal(t.events.filter((e) => e.stepId === 'mcp-validate').length, 5);
  assertNoLeaks(t);
});

test('MCP: token for the wrong audience is rejected (no token passthrough)', async () => {
  const tok = await userToken('api-client-id', 'access_as_user');
  const res = await post('/mcp', { jsonrpc: '2.0', id: 1, method: 'tools/list' }, { authorization: `Bearer ${tok}` });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate'), /error="invalid_token"/);
});
