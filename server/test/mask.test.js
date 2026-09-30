import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeJwt, maskToken, maskForm, maskJsonBody, maskHeaders, scrubDeep, SECRET_MASK, truncateText, maskUpn, maskUpnsDeep,
} from '../src/mask.js';
import { fakeJwt } from './helpers.js';

test('decodeJwt decodes header and payload without verification', () => {
  const { raw } = fakeJwt({ aud: 'x', scp: 'User.Read' });
  const d = decodeJwt(raw);
  assert.deepEqual(d.header, { alg: 'RS256', typ: 'JWT', kid: 'test-kid' });
  assert.deepEqual(d.payload, { aud: 'x', scp: 'User.Read' });
});

test('decodeJwt returns null for non-JWTs', () => {
  for (const v of [null, undefined, 42, '', 'abc', 'a.b', 'a.b.c', '0.AXoA.abc', 'eyJ.eyJ.x', `${'x'.repeat(10)}.${'y'.repeat(10)}.z`]) {
    assert.equal(decodeJwt(v), null, String(v));
  }
});

test('maskToken masks JWTs with header/payload prefixes and redacts the signature', () => {
  const { raw, signature } = fakeJwt({ sub: 'user' });
  const [h, p] = raw.split('.');
  const m = maskToken(raw);
  assert.equal(m, `${h.slice(0, 16)}….${p.slice(0, 12)}….[signature redacted]`);
  assert.ok(!m.includes(signature.slice(0, 16)));
  assert.ok(!m.includes(p));
});

test('maskToken masks opaque values to 6 chars', () => {
  assert.equal(maskToken('0.AXoAabcdefghijk'), '0.AXoA…[redacted]');
});

test('maskForm redacts secrets, masks token fields and collects JWTs', () => {
  const assertion = fakeJwt({ iss: 'client' });
  const { body, tokens } = maskForm({
    grant_type: 'client_credentials',
    client_id: 'cid',
    client_secret: 'super-secret-value',
    client_assertion: assertion.raw,
    code: 'OAQABAAIAAAAm-long-auth-code',
    code_verifier: 'verifier-1234567890',
    device_code: 'DAQABAAEAAAD-device',
    refresh_token: '0.AXoA-refresh',
  });
  assert.equal(body.grant_type, 'client_credentials');
  assert.equal(body.client_id, 'cid');
  assert.equal(body.client_secret, SECRET_MASK);
  assert.equal(body.client_assertion, maskToken(assertion.raw));
  assert.equal(body.code, 'OAQABA…');
  assert.equal(body.code_verifier, 'verifi…');
  assert.equal(body.device_code, 'DAQABA…');
  assert.equal(body.refresh_token, '0.AXoA…');
  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].label, 'client_assertion');
  assert.deepEqual(tokens[0].payload, { iss: 'client' });
  const s = JSON.stringify({ body, tokens });
  assert.ok(!s.includes('super-secret-value'));
  assert.ok(!s.includes(assertion.signature));
  assert.ok(!s.includes('long-auth-code'));
});

test('maskJsonBody masks token response fields and collects decoded tokens', () => {
  const at = fakeJwt({ aud: 'https://graph.microsoft.com' });
  const id = fakeJwt({ name: 'Ada' });
  const { body, tokens } = maskJsonBody({
    token_type: 'Bearer', expires_in: 3599, access_token: at.raw, id_token: id.raw, refresh_token: '1.AXoA-opaque-refresh',
  });
  assert.equal(body.token_type, 'Bearer');
  assert.equal(body.expires_in, 3599);
  assert.equal(body.access_token, maskToken(at.raw));
  assert.equal(body.refresh_token, '1.AXoA…[redacted]');
  assert.deepEqual(tokens.map((t) => t.label), ['access_token', 'id_token']);
  const s = JSON.stringify({ body, tokens });
  assert.ok(!s.includes(at.signature) && !s.includes(id.signature) && !s.includes('opaque-refresh'));
});

test('maskHeaders masks Authorization bearer tokens', () => {
  const at = fakeJwt({ scp: 'User.Read' });
  const { headers, tokens } = maskHeaders({ Authorization: `Bearer ${at.raw}`, Accept: 'application/json' });
  assert.equal(headers.Authorization, `Bearer ${maskToken(at.raw)}`);
  assert.equal(headers.Accept, 'application/json');
  assert.equal(tokens[0].label, 'access_token');
  assert.ok(!JSON.stringify({ headers, tokens }).includes(at.signature));
});

test('scrubDeep masks embedded JWTs and known secrets anywhere', () => {
  const at = fakeJwt({ a: 1 });
  const out = scrubDeep({ note: `leaked ${at.raw} and s3cr3t-value!`, nested: [{ x: at.raw }] }, ['s3cr3t-value']);
  const s = JSON.stringify(out);
  assert.ok(!s.includes(at.signature));
  assert.ok(!s.includes('s3cr3t-value'));
  assert.ok(s.includes('[signature redacted]'));
});

test('truncateText caps at 4kb', () => {
  const t = truncateText('x'.repeat(5000));
  assert.ok(t.startsWith('x'.repeat(4096)));
  assert.ok(t.length < 4200);
});

test('maskUpn keeps 3 chars and the domain', () => {
  assert.equal(maskUpn('adele.vance@contoso.com'), 'ade…@contoso.com');
  assert.equal(maskUpn('al@contoso.com'), 'al…@contoso.com');
  assert.equal(maskUpn('ada_fabrikam.com#EXT#@contoso.onmicrosoft.com'), 'ada…@contoso.onmicrosoft.com');
  assert.equal(maskUpn('no-at-sign'), 'no-…');
  for (const v of [null, undefined, '', 42]) assert.equal(maskUpn(v), v);
});

test('maskUpnsDeep masks every userPrincipalName and leaves other fields', () => {
  const input = { value: [{ id: 'r1', userPrincipalName: 'megan.bowen@contoso.com', riskEventType: 'anonymizedIPAddress', nested: { UserPrincipalName: 'joni@contoso.com' } }] };
  const out = maskUpnsDeep(input);
  assert.deepEqual(out, { value: [{ id: 'r1', userPrincipalName: 'meg…@contoso.com', riskEventType: 'anonymizedIPAddress', nested: { UserPrincipalName: 'jon…@contoso.com' } }] });
  assert.equal(input.value[0].userPrincipalName, 'megan.bowen@contoso.com', 'input not mutated');
});
