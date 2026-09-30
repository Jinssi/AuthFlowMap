import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';
import { buildConfig } from '../src/config.js';
import { listen, fakeJwt } from './helpers.js';

// No tenant config at all: must not depend on the developer's .env.
const cfg = buildConfig({});
let srv;

test.before(async () => {
  srv = await listen(createApp({ cfg, log: () => {} }));
});
test.after(async () => {
  await srv.close();
});

test('GET /api/health reports live:false and never includes secrets', async () => {
  const res = await fetch(`${srv.base}/api/health`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(res.headers.get('access-control-allow-origin'), null);
  const j = await res.json();
  assert.equal(j.ok, true);
  assert.equal(j.live, false);
  assert.equal(j.redirectUri, 'http://localhost:5100/auth-callback');
  assert.deepEqual(Object.keys(j.flows).sort(), [
    'agent-autonomous', 'agent-obo', 'aitm', 'auth-code-pkce', 'ca-sim', 'client-credentials', 'device-code', 'device-sso',
    'id-protection', 'mcp-auth', 'mcp-obo', 'obo', 'step-up', 'web-app',
  ]);
  assert.deepEqual(j.flows['client-credentials'], { secret: false, certificate: false });
  assert.deepEqual(j.flows['web-app'], { secret: false, certificate: false });
  assert.equal(j.scopes.graph, 'openid profile offline_access User.Read');
  assert.equal(j.stepUpAuthContext, 'c1');
  assert.deepEqual(j.whatIfSubjects, { user: false, workload: false, agent: false });
  assert.deepEqual(Object.keys(j.ids).sort(), ['agentIdentityAppId', 'apiClientId', 'blueprintAppId', 'daemonClientId', 'mcpClientId', 'webAppClientId']);
  // Only the spec'd boolean flag flows['client-credentials'].secret may mention "secret".
  assert.ok(!/client_?secret|secret"\s*:\s*"/i.test(JSON.stringify(j)));
  assert.ok(!/key_?path|cert_?path/i.test(JSON.stringify(j)));
});

test('health with config: flags true, secrets never returned', async () => {
  const env = {
    TENANT_ID: 'contoso.onmicrosoft.com', SPA_CLIENT_ID: 'spa', API_CLIENT_ID: 'api', API_CLIENT_SECRET: 'VERY-SECRET-1',
    DAEMON_CLIENT_ID: 'daemon', DAEMON_CLIENT_SECRET: 'VERY-SECRET-2', DAEMON_CERT_PATH: 'nope.pem', DAEMON_KEY_PATH: 'nope.key',
  };
  const s = await listen(createApp({ cfg: buildConfig(env), log: () => {} }));
  try {
    const j = await (await fetch(`${s.base}/api/health`)).json();
    assert.equal(j.live, true);
    assert.equal(j.flows.obo, true);
    assert.deepEqual(j.flows['client-credentials'], { secret: true, certificate: false });
    assert.equal(j.flows['mcp-auth'], false);
    assert.equal(j.scopes.api, 'api://api/access_as_user');
    assert.ok(!JSON.stringify(j).includes('VERY-SECRET'));
  } finally {
    await s.close();
  }
});

test('GET /api/health reports new flow flags, methods scope, auth context and What If subjects', async () => {
  const base = {
    TENANT_ID: 'contoso.onmicrosoft.com', SPA_CLIENT_ID: 'spa', API_CLIENT_ID: 'api', API_CLIENT_SECRET: 'VERY-SECRET-1',
    DAEMON_CLIENT_ID: 'daemon', DAEMON_CLIENT_SECRET: 'VERY-SECRET-2',
  };
  const on = { ...base, DEMO_USER_ID: 'aaaaaaaa-0000-0000-0000-000000000001', DAEMON_SP_ID: 'aaaaaaaa-0000-0000-0000-000000000002', STEPUP_ENABLED: 'true', STEPUP_AUTH_CONTEXT: 'c7' };
  for (const [env, expected] of [
    [base, { 'step-up': false, 'ca-sim': false, aitm: true, 'device-sso': true, 'id-protection': true, ctx: 'c1', subjects: { user: false, workload: false, agent: false } }],
    [on, { 'step-up': true, 'ca-sim': true, aitm: true, 'device-sso': true, 'id-protection': true, ctx: 'c7', subjects: { user: true, workload: true, agent: false } }],
    [{ ...on, STEPUP_AUTH_CONTEXT: 'c100', DAEMON_CLIENT_SECRET: '' }, { 'step-up': true, 'ca-sim': false, aitm: true, 'device-sso': true, 'id-protection': false, ctx: 'c1', subjects: { user: true, workload: true, agent: false } }],
  ]) {
    const s = await listen(createApp({ cfg: buildConfig(env), log: () => {} }));
    try {
      const j = await (await fetch(`${s.base}/api/health`)).json();
      for (const k of ['step-up', 'ca-sim', 'aitm', 'device-sso', 'id-protection']) assert.equal(j.flows[k], expected[k], k);
      assert.equal(j.scopes.methods, 'openid profile offline_access User.Read UserAuthenticationMethod.Read');
      assert.equal(j.stepUpAuthContext, expected.ctx);
      assert.deepEqual(j.whatIfSubjects, expected.subjects);
      assert.ok(!JSON.stringify(j).includes('VERY-SECRET'));
      assert.ok(!JSON.stringify(j).includes('aaaaaaaa-0000'));
    } finally {
      await s.close();
    }
  }
});

test('GET /.well-known/oauth-protected-resource/mcp shape (RFC 9728)', async () => {
  for (const p of ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource']) {
    const res = await fetch(`${srv.base}${p}`);
    assert.equal(res.status, 200);
    const j = await res.json();
    assert.equal(j.resource, 'http://localhost:5100/mcp');
    assert.ok(Array.isArray(j.authorization_servers) && j.authorization_servers.length === 1);
    assert.match(j.authorization_servers[0], /^https:\/\/login\.microsoftonline\.com\/.+\/v2\.0$/);
    assert.deepEqual(j.bearer_methods_supported, ['header']);
    assert.equal(j.scopes_supported.length, 1);
    assert.equal(j.resource_name, 'AuthFlow demo MCP server');
  }
});

test('POST /mcp without token -> 401 with resource_metadata challenge', async () => {
  const res = await fetch(`${srv.base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }),
  });
  assert.equal(res.status, 401);
  const www = res.headers.get('www-authenticate');
  assert.match(www, /^Bearer resource_metadata="http:\/\/localhost:5100\/\.well-known\/oauth-protected-resource\/mcp", scope="api:\/\/.*\/mcp\.tools"$/);
  const j = await res.json();
  assert.equal(j.jsonrpc, '2.0');
  assert.equal(j.id, 1);
  assert.ok(j.error.code);
});

test('POST /mcp with invalid token -> 401 with error="invalid_token"', async () => {
  const res = await fetch(`${srv.base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${fakeJwt({}).raw}` },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
  });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate'), /resource_metadata=".*", scope=".*", error="invalid_token"/);
});

test('GET /api/obo/me without token -> 401 invalid_token', async () => {
  const res = await fetch(`${srv.base}/api/obo/me`, { headers: { 'x-run-id': 'obo-run-0001' } });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate'), /^Bearer error="invalid_token"/);
  const j = await res.json();
  assert.equal(j.error, 'invalid_token');
  assert.ok(Array.isArray(j.checks));
  const t = await (await fetch(`${srv.base}/api/trace/obo-run-0001`)).json();
  assert.equal(t.done, true);
  assert.equal(t.events[0].stepId, 'obo-validate');
  assert.equal(t.events[0].status, 'error');
});

test('POST /api/agent/obo without token -> 401', async () => {
  const res = await fetch(`${srv.base}/api/agent/obo`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ prompt: 'hi' }),
  });
  assert.equal(res.status, 401);
});

test('POST /api/stepup/approve without token -> 401 invalid_token, run done', async () => {
  const res = await fetch(`${srv.base}/api/stepup/approve`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-run-id': 'su-run-0000' }, body: JSON.stringify({ paymentId: 'p1', amount: 1 }),
  });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate'), /error="invalid_token"/);
  const t = await (await fetch(`${srv.base}/api/trace/su-run-0000`)).json();
  assert.equal(t.done, true);
  assert.equal(t.events[0].stepId, 'su-validate');
  assert.deepEqual(t.events[0].checks.at(-1), { name: 'acrs contains c1', ok: false, detail: 'no acrs claim' });
});

test('trace endpoint: runId validation and unknown run', async () => {
  assert.equal((await fetch(`${srv.base}/api/trace/bad`)).status, 400);
  const j = await (await fetch(`${srv.base}/api/trace/never-seen-run?since=3`)).json();
  assert.deepEqual(j, { events: [], done: false, error: null });
  const bad = await fetch(`${srv.base}/api/obo/me`, { headers: { 'x-run-id': 'x' } });
  assert.equal(bad.status, 400);
});

test('server-run flows reject bad input / missing config', async () => {
  const post = (p, body) => fetch(`${srv.base}${p}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await post('/api/live/id-protection', { runId: 'run-ok-005' })).status, 503);
  assert.equal((await post('/api/live/ca-whatif', { runId: 'run-ok-006', subject: 'user', context: { type: 'authContext', value: 'c1' } })).status, 503);
  assert.equal((await post('/api/live/ca-whatif', { runId: 'run-ok-006', subject: 'root', context: { type: 'authContext', value: 'c1' } })).status, 400);
  assert.equal((await post('/api/live/client-credentials', { runId: 'no' })).status, 400);
  assert.equal((await post('/api/live/client-credentials', { runId: 'run-ok-001', variant: 'magic' })).status, 400);
  assert.equal((await post('/api/live/client-credentials', { runId: 'run-ok-001', variant: 'secret' })).status, 503);
  assert.equal((await post('/api/live/device-code', { runId: 'run-ok-002' })).status, 503);
  assert.equal((await post('/api/live/agent-autonomous', { runId: 'run-ok-003' })).status, 503);
});

test('cross-origin POST and foreign Host are refused', async () => {
  const res = await fetch(`${srv.base}/api/live/device-code`, {
    method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://evil.example' }, body: '{"runId":"run-ok-004"}',
  });
  assert.equal(res.status, 403);
  const { request } = await import('node:http');
  const status = await new Promise((resolve, reject) => {
    const r = request(`${srv.base}/api/health`, { headers: { host: 'evil.example' } }, (resp) => { resp.resume(); resolve(resp.statusCode); });
    r.on('error', reject);
    r.end();
  });
  assert.equal(status, 403);
});

test('GET /auth-callback posts message to opener, no external resources', async () => {
  const res = await fetch(`${srv.base}/auth-callback?code=abc&state=xyz`);
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /authflow-callback/);
  assert.match(html, /window\.opener\.postMessage\(msg, location\.origin\)/);
  assert.match(html, /You can close this window/);
  assert.ok(!/(src|href)=["']?https?:/i.test(html));
});

test('GET / serves index.html or build hint', async () => {
  const res = await fetch(`${srv.base}/`);
  if (res.status === 404) assert.equal(await res.text(), 'Run: node demonstrator/build.mjs');
  else assert.equal(res.status, 200);
});

test('invalid JSON on /mcp -> JSON-RPC parse error', async () => {
  const res = await fetch(`${srv.base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{nope' });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, -32700);
});
