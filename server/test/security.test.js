// Step-up, Conditional Access What If and Identity Protection with mocked Entra/Graph and a local JWKS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createApp } from '../src/server.js';
import { buildConfig } from '../src/config.js';
import { parseWhatIfRequest, buildEvaluateBody } from '../src/flows/caWhatIf.js';
import { listen, fakeJwt, jsonResponse, waitDone, TEST_ENV, TENANT } from './helpers.js';

const USER_OID = '0a0a0a0a-1111-2222-3333-444444444444';
const DAEMON_SP = '0b0b0b0b-1111-2222-3333-444444444444';
const AGENT_SP = '0c0c0c0c-1111-2222-3333-444444444444';
const APP1 = '00000003-0000-0000-c000-000000000000';
const ENV = {
  ...TEST_ENV, DEMO_USER_ID: USER_OID, DAEMON_SP_ID: DAEMON_SP, AGENT_IDENTITY_SP_ID: AGENT_SP, STEPUP_ENABLED: 'true',
};
const cfg = buildConfig(ENV);
const SECRETS = Object.entries(TEST_ENV).filter(([k]) => k.endsWith('SECRET')).map(([, v]) => v);
const issued = [];

const calls = [];
let evaluateStatus = 200;
async function mockFetch(url, init = {}) {
  const u = String(url);
  const isForm = String(init.headers?.['Content-Type'] ?? '').includes('x-www-form-urlencoded');
  const form = init.body && isForm ? Object.fromEntries(new URLSearchParams(init.body)) : null;
  const json = init.body && !isForm ? JSON.parse(init.body) : null;
  calls.push({ url: u, method: init.method, form, json, headers: init.headers });
  if (u.endsWith('/oauth2/v2.0/token')) {
    const t = fakeJwt({ aud: 'https://graph.microsoft.com', roles: ['Policy.Read.ConditionalAccess'] });
    issued.push(t);
    return jsonResponse(200, { token_type: 'Bearer', expires_in: 3599, access_token: t.raw });
  }
  if (u === 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/evaluate') {
    if (evaluateStatus !== 200) {
      return jsonResponse(evaluateStatus, { error: { code: 'Authorization_RequestDenied', message: 'Insufficient privileges to complete the operation.' } });
    }
    return jsonResponse(200, {
      '@odata.context': 'https://graph.microsoft.com/v1.0/$metadata#Collection(microsoft.graph.whatIfAnalysisResult)',
      value: [
        { id: 'p1', displayName: 'Block legacy auth', state: 'enabled', policyApplies: false, analysisReasons: 'clientApps', grantControls: { operator: 'OR', builtInControls: ['block'] }, sessionControls: null, conditions: {} },
        { id: 'p2', displayName: 'Require MFA', state: 'enabled', policyApplies: true, analysisReasons: 'notSet', grantControls: { operator: 'OR', builtInControls: ['mfa'] }, sessionControls: null },
        { id: 'p3', displayName: 'Admins compliant device', state: 'enabledForReportingButNotEnforced', policyApplies: true, analysisReasons: 'notSet', grantControls: null, sessionControls: { signInFrequency: { value: 1 } } },
      ],
    });
  }
  if (u.startsWith('https://graph.microsoft.com/v1.0/identityProtection/riskDetections')) {
    return jsonResponse(403, { error: { code: 'Forbidden', message: 'Your tenant is not licensed for this feature.' } });
  }
  if (u.startsWith('https://graph.microsoft.com/v1.0/identityProtection/riskyUsers')) {
    return jsonResponse(200, {
      value: [
        { id: 'u1', userDisplayName: 'Megan', userPrincipalName: 'megan.bowen@contoso.test', riskLevel: 'high', riskState: 'atRisk' },
        { id: 'u2', userDisplayName: 'Joni', userPrincipalName: 'joni.sherman@contoso.test', riskLevel: 'low', riskState: 'atRisk' },
      ],
    });
  }
  return jsonResponse(404, { error: { code: 'NotFound', message: 'no mock' } });
}

let srv;
let app;
let privateKey;

async function userToken(extra = {}) {
  const raw = await new SignJWT({ scp: 'access_as_user', tid: TENANT, name: 'Ada', ...extra })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1', typ: 'JWT' })
    .setIssuer(cfg.issuerV2).setAudience('api-client-id').setIssuedAt().setExpirationTime('10m')
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
}

test.before(async () => {
  const kp = await generateKeyPair('RS256');
  privateKey = kp.privateKey;
  const jwk = { ...(await exportJWK(kp.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
  app = createApp({ cfg, fetchImpl: mockFetch, jwks: createLocalJWKSet({ keys: [jwk] }), sleep: async () => {}, log: () => {} });
  srv = await listen(app);
});
test.after(async () => srv.close());

const trace = () => app.locals.ctx.trace;
const post = (p, body, headers = {}) => fetch(`${srv.base}${p}`, {
  method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body),
});

// ---------- step-up ----------

test('step-up: no acrs -> 401 insufficient_claims challenge, then acrs [c1] -> 200 approved', async () => {
  const runId = 'su-run-0001';
  let tok = await userToken();
  let res = await post('/api/stepup/approve', { paymentId: 'PAY-42', amount: 1250.5 }, { authorization: `Bearer ${tok}`, 'x-run-id': runId });
  assert.equal(res.status, 401);
  const claims = '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}';
  const b64 = Buffer.from(claims).toString('base64');
  const www = res.headers.get('www-authenticate');
  assert.equal(www, `Bearer realm="", authorization_uri="https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/authorize", error="insufficient_claims", claims="${b64}"`);
  assert.deepEqual(await res.json(), { error: 'insufficient_claims', error_description: 'This action needs step-up authentication', claims });
  let t = trace().get(runId);
  assert.equal(t.done, true);
  assert.deepEqual(t.events.map((e) => e.stepId), ['su-validate', 'su-challenge']);
  const [val, ch] = t.events;
  assert.equal(val.label, 'Validate token and acrs');
  assert.equal(val.checks.length, 7);
  assert.ok(val.checks.slice(0, 6).every((c) => c.ok));
  assert.deepEqual(val.checks[6], { name: 'acrs contains c1', ok: false, detail: 'no acrs claim' });
  assert.deepEqual([ch.from, ch.to, ch.label, ch.determinism, ch.status], ['api', 'browser', '401 insufficient_claims', 'policy', 'ok']);
  assert.equal(ch.response.status, 401);
  assert.equal(ch.response.headers['www-authenticate'], www);
  assert.deepEqual(ch.data, { claims });

  tok = await userToken({ acrs: ['c1'] });
  res = await post('/api/stepup/approve', { paymentId: 'PAY-42', amount: 1250.5 }, { authorization: `Bearer ${tok}`, 'x-run-id': runId });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { approved: true, paymentId: 'PAY-42', amount: 1250.5, approvedBy: 'Ada', acrs: ['c1'] });
  t = trace().get(runId);
  assert.equal(t.done, true);
  assert.equal(t.error, null);
  assert.deepEqual(t.events.map((e) => e.stepId), ['su-validate', 'su-challenge', 'su-validate', 'su-approve']);
  assert.deepEqual(t.events[2].checks[6], { name: 'acrs contains c1', ok: true, detail: 'c1' });
  const ap = t.events[3];
  assert.deepEqual([ap.from, ap.to, ap.label, ap.determinism], ['api', 'api', 'Payment approved', 'protocol']);
  assert.deepEqual(ap.data, { paymentId: 'PAY-42', amount: 1250.5 });
  assertNoLeaks(t);
});

test('step-up: bad body -> 400, wrong audience -> 401 invalid_token', async () => {
  const tok = await userToken({ acrs: ['c1'] });
  for (const body of [{ paymentId: 'x'.repeat(65), amount: 1 }, { paymentId: 'p', amount: '1' }, { amount: 1 }]) {
    const res = await post('/api/stepup/approve', body, { authorization: `Bearer ${tok}` });
    assert.equal(res.status, 400, JSON.stringify(body));
  }
  const res = await post('/api/stepup/approve', { paymentId: 'p', amount: 1 }, { authorization: `Bearer ${fakeJwt({ aud: 'x' }).raw}`, 'x-run-id': 'su-run-0002' });
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error, 'invalid_token');
  assert.equal(trace().get('su-run-0002').done, true);
});

// ---------- CA What If ----------

const baseWhatIf = (over = {}) => ({ runId: 'wi-run-0000', subject: 'user', context: { type: 'app', appIds: [APP1] }, ...over });

test('ca-whatif validation rejects bad enums, GUIDs, countries and unknown fields', () => {
  const bad = [
    { conditions: { devicePlatform: 'ios' } },
    { conditions: { devicePlatform: 'windowsPhone' } },
    { conditions: { clientAppType: 'legacy' } },
    { conditions: { signInRiskLevel: 'hidden' } },
    { conditions: { insiderRiskLevel: 'high' } },
    { conditions: { country: 'us' } },
    { conditions: { country: 'USA' } },
    { conditions: { ipAddress: '999.1.1.1' } },
    { conditions: { ipAddress: 'localhost' } },
    { conditions: { deviceCompliant: 'true' } },
    { conditions: { deviceTrustType: 'azuread' } },
    { conditions: { deviceCodeFlow: 1 } },
    { conditions: { evil: 1 } },
    { conditions: [] },
    { context: { type: 'app', appIds: ['not-a-guid'] } },
    { context: { type: 'app', appIds: [] } },
    { context: { type: 'app', appIds: Array(6).fill(APP1) } },
    { context: { type: 'app', appIds: [APP1], extra: true } },
    { context: { type: 'authContext', value: 'c0' } },
    { context: { type: 'authContext', value: 'c100' } },
    { context: { type: 'other' } },
    { context: undefined },
    { subject: 'admin' },
    { runId: 'bad' },
    { extra: 1 },
  ];
  for (const over of bad) assert.equal(parseWhatIfRequest(baseWhatIf(over)).ok, false, JSON.stringify(over));
  assert.equal(parseWhatIfRequest(null).ok, false);

  const good = parseWhatIfRequest(baseWhatIf({
    conditions: {
      devicePlatform: 'iOS', clientAppType: 'browser', country: 'FI', ipAddress: '2001:db8::1', signInRiskLevel: 'high',
      userRiskLevel: 'none', servicePrincipalRiskLevel: 'low', insiderRiskLevel: 'elevated', deviceCompliant: false,
      deviceTrustType: null, deviceCodeFlow: true,
    },
    context: { type: 'authContext', value: 'c99' },
  }));
  assert.equal(good.ok, true);
  assert.equal('deviceTrustType' in good.value.conditions, false);
  assert.equal(parseWhatIfRequest(baseWhatIf({ conditions: { ipAddress: '203.0.113.9' } })).ok, true);
});

test('ca-whatif body mapping: subjects, contexts, deviceInfo, authenticationFlow, omitted fields', () => {
  const user = buildEvaluateBody(cfg, parseWhatIfRequest(baseWhatIf()).value);
  assert.deepEqual(user, {
    signInIdentity: { '@odata.type': '#microsoft.graph.userSignIn', userId: USER_OID },
    signInContext: { '@odata.type': '#microsoft.graph.applicationContext', includeApplications: [APP1] },
    signInConditions: {},
    appliedPoliciesOnly: false,
  });
  const wl = buildEvaluateBody(cfg, parseWhatIfRequest(baseWhatIf({ subject: 'workload', conditions: { deviceTrustType: 'Workplace' } })).value);
  assert.deepEqual(wl.signInIdentity, { '@odata.type': '#microsoft.graph.servicePrincipalSignIn', servicePrincipalId: DAEMON_SP });
  assert.deepEqual(wl.signInConditions, { deviceInfo: { trustType: 'Workplace' } });
  const ag = buildEvaluateBody(cfg, parseWhatIfRequest(baseWhatIf({ subject: 'agent', context: { type: 'authContext', value: 'c3' }, conditions: { deviceCodeFlow: false } })).value);
  assert.deepEqual(ag.signInIdentity, { '@odata.type': '#microsoft.graph.servicePrincipalSignIn', servicePrincipalId: AGENT_SP });
  assert.deepEqual(ag.signInContext, { '@odata.type': '#microsoft.graph.authContext', authenticationContextValue: 'c3' });
  assert.deepEqual(ag.signInConditions, {});
});

test('ca-whatif end to end: token, evaluate request/response traced, policies sorted applies-first', async () => {
  calls.length = 0;
  evaluateStatus = 200;
  const conditions = {
    devicePlatform: 'windows', clientAppType: 'browser', country: 'FI', ipAddress: '203.0.113.9', signInRiskLevel: 'medium',
    deviceCompliant: true, deviceTrustType: 'AzureAd', deviceCodeFlow: true,
  };
  const res = await post('/api/live/ca-whatif', baseWhatIf({ runId: 'wi-run-0001', conditions }));
  assert.equal(res.status, 200);
  const j = await res.json();
  assert.deepEqual(j.policies.map((p) => [p.id, p.policyApplies]), [['p3', true], ['p2', true], ['p1', false]]);
  assert.deepEqual(Object.keys(j.policies[0]).sort(), ['analysisReasons', 'displayName', 'grantControls', 'id', 'policyApplies', 'sessionControls', 'state']);
  assert.deepEqual(j.policies[1].grantControls, { operator: 'OR', builtInControls: ['mfa'] });

  const sent = calls.find((c) => c.url.endsWith('/conditionalAccess/evaluate'));
  assert.equal(sent.method, 'POST');
  assert.match(sent.headers.Authorization, /^Bearer ey/);
  assert.deepEqual(sent.json, {
    signInIdentity: { '@odata.type': '#microsoft.graph.userSignIn', userId: USER_OID },
    signInContext: { '@odata.type': '#microsoft.graph.applicationContext', includeApplications: [APP1] },
    signInConditions: {
      devicePlatform: 'windows', clientAppType: 'browser', country: 'FI', ipAddress: '203.0.113.9', signInRiskLevel: 'medium',
      authenticationFlow: { transferMethod: 'deviceCodeFlow' }, deviceInfo: { isCompliant: true, trustType: 'AzureAd' },
    },
    appliedPoliciesOnly: false,
  });
  const tokenCall = calls.find((c) => c.url.endsWith('/oauth2/v2.0/token'));
  assert.equal(tokenCall.form.client_id, 'daemon-client-id');
  assert.equal(tokenCall.form.scope, 'https://graph.microsoft.com/.default');

  const t = trace().get('wi-run-0001');
  assert.equal(t.done, true);
  assert.equal(t.error, null);
  assert.deepEqual(t.events.map((e) => e.stepId), ['wi-token-req', 'wi-token-res', 'wi-eval-req', 'wi-eval-res']);
  assert.deepEqual([t.events[0].from, t.events[0].to], ['daemon', 'entra']);
  const ereq = t.events[2];
  assert.deepEqual([ereq.from, ereq.to, ereq.label], ['daemon', 'graph', 'POST /identity/conditionalAccess/evaluate']);
  assert.deepEqual(ereq.request.body, sent.json);
  assert.match(ereq.request.headers.Authorization, /\[signature redacted\]$/);
  assert.deepEqual([t.events[3].from, t.events[3].to, t.events[3].status], ['graph', 'daemon', 'ok']);
  assert.deepEqual(t.events[3].data, { policies: 3, applying: 2 });
  assertNoLeaks(t);
});

test('ca-whatif Graph 403 -> 502 with error, run finished with error', async () => {
  evaluateStatus = 403;
  try {
    const res = await post('/api/live/ca-whatif', baseWhatIf({ runId: 'wi-run-0002', subject: 'workload' }));
    assert.equal(res.status, 502);
    const j = await res.json();
    assert.equal(j.error, 'Authorization_RequestDenied');
    assert.match(j.error_description, /Insufficient privileges.*Policy\.Read\.ConditionalAccess/);
    const t = trace().get('wi-run-0002');
    assert.equal(t.done, true);
    assert.match(t.error, /Authorization_RequestDenied/);
    assert.equal(t.events.at(-1).stepId, 'wi-eval-res');
    assert.equal(t.events.at(-1).status, 'error');
  } finally {
    evaluateStatus = 200;
  }
});

// ---------- Identity Protection ----------

test('id-protection: detections 403 + risky users 200 still completes with ip-summary; UPNs masked', async () => {
  const res = await post('/api/live/id-protection', { runId: 'ip-run-0001' });
  assert.equal(res.status, 202);
  const t = await waitDone(trace(), 'ip-run-0001');
  assert.equal(t.error, null);
  assert.deepEqual(t.events.map((e) => e.stepId), ['ip-token-req', 'ip-token-res', 'ip-det-req', 'ip-det-res', 'ip-users-req', 'ip-users-res', 'ip-summary']);
  assert.match(t.events[2].request.url, /\/identityProtection\/riskDetections\?\$top=5&\$orderby=detectedDateTime%20desc$/);
  assert.equal(t.events[3].status, 'error');
  assert.equal(t.events[3].response.status, 403);
  assert.equal(t.events[5].status, 'ok');
  assert.deepEqual(t.events[5].response.body.value.map((u) => u.userPrincipalName), ['meg…@contoso.test', 'jon…@contoso.test']);
  const sum = t.events[6];
  assert.deepEqual([sum.from, sum.to, sum.label, sum.determinism, sum.status], ['daemon', 'daemon', 'Summarise risk', 'policy', 'ok']);
  assert.equal(sum.note, 'Needs Entra ID P2 and IdentityRiskEvent.Read.All / IdentityRiskyUser.Read.All');
  assert.deepEqual(sum.data, { detections: null, riskyUsers: 2, topRiskEventTypes: [] });
  const s = JSON.stringify(t);
  assert.ok(!s.includes('megan.bowen') && !s.includes('joni.sherman'), 'UPN leaked into trace');
  assertNoLeaks(t);
});
