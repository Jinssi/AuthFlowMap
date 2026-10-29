// Value-based masking safety net: token-shaped values must not survive anywhere in a trace,
// whatever the field name or nesting. Seeded PRNG so failures are reproducible.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { scrubDeep, scrubText, SECRET_MASK } from '../src/mask.js';
import { TraceStore } from '../src/trace.js';

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const SECRET_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_~.-';

function makeGen(seed) {
  const rnd = mulberry32(seed);
  const int = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
  const pick = (arr) => arr[Math.floor(rnd() * arr.length)];
  const chars = (alphabet, n) => {
    let s = '';
    for (let i = 0; i < n; i += 1) s += alphabet[Math.floor(rnd() * alphabet.length)];
    // Make sure every class is present so the value really is token-shaped.
    return `${s.slice(0, -3)}${pick('ABCDEFGHJKMNPQRSTUVWXYZ')}${pick('abcdefghjkmnpqrstuvwxyz')}${int(0, 9)}`;
  };
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const name = () => chars('abcdefghijklmnopqrstuvwxyz_', int(3, 12)).replace(/[^a-z_]/g, 'q');

  // Each token: the raw value and the part that must never appear in output.
  const kinds = {
    jwt: () => {
      const raw = `${enc({ alg: 'RS256', typ: 'JWT', kid: name() })}.${enc({ aud: name(), oid: crypto.randomUUID(), [name()]: name() })}.${chars(B64URL, 342)}`;
      return { raw, secret: raw.split('.')[2] };
    },
    brokenJwt: () => {
      const raw = `eyJ${chars(B64URL, int(20, 60))}.${chars(B64URL, int(20, 200))}.${chars(B64URL, int(30, 300))}`;
      return { raw, secret: raw.slice(6) };
    },
    jwe: () => {
      const raw = `${enc({ alg: 'RSA-OAEP', enc: 'A256GCM' })}.${chars(B64URL, 342)}.${chars(B64URL, 16)}.${chars(B64URL, 200)}.${chars(B64URL, 22)}`;
      return { raw, secret: raw.split('.').slice(1).join('.') };
    },
    refresh: () => {
      const raw = `${pick(['0.AXoA', '1.AXoA', '0.ASoA', '1.AUEB'])}${chars(B64URL, int(100, 300))}.${chars(B64URL, int(100, 300))}`;
      return { raw, secret: raw.slice(6) };
    },
    authCode: () => {
      const raw = `${pick(['M.C5_BAY.2.U.', '1.AXoA', 'OAQABAAIAAAA'])}${chars(B64URL, int(64, 400))}`;
      return { raw, secret: raw.slice(13) };
    },
    deviceCode: () => {
      const raw = `DAQABAAEAAAD${chars(B64URL, int(120, 200))}`;
      return { raw, secret: raw.slice(6) };
    },
    clientSecret: () => {
      const raw = `${chars(SECRET_CHARS, 3).replace(/\d$/, 'x')}${int(0, 9)}Q~${chars(SECRET_CHARS, 34).replace(/[.~-]+$/, 'z')}`;
      return { raw, secret: raw.slice(6) };
    },
    bearer: () => {
      const value = chars(B64URL, int(24, 60));
      return { raw: `Bearer ${value}`, secret: value.slice(6), encoded: `Bearer%20${value}` };
    },
  };

  const contexts = [
    (t) => t.raw,
    (t) => `${pick(['Error:', 'AADSTS50000 failed for', 'leaked', '>>'])} ${t.raw} ${pick(['while redeeming.', 'Trace ID: x', '', '(retry)'])}`,
    (t) => `https://${name()}.example/cb?${name()}=${encodeURIComponent(t.encoded ? t.encoded.replace('Bearer%20', 'Bearer ') : t.raw)}&${name()}=1`,
    (t) => `https://${name()}.example/cb?${name()}=${t.encoded ?? t.raw}#${name()}`,
    (t) => `${name()}=1&${name()}=${t.raw}&${name()}=x`,
    (t) => JSON.stringify({ [name()]: t.raw, [name()]: 'ok' }),
    (t) => `{"error":"invalid_grant","error_description":"bad value ${t.raw}"}`,
    (t) => `${name()}:${t.raw}`,
  ];

  function nest(leaf, depth) {
    if (depth === 0) return leaf;
    switch (int(0, 3)) {
      case 0: return [name(), nest(leaf, depth - 1), int(0, 100)];
      case 1: return { [name()]: nest(leaf, depth - 1), [name()]: name() };
      case 2: return { [name()]: [{ [name()]: nest(leaf, depth - 1) }] };
      default: return { [name()]: null, [name()]: true, [name()]: nest(leaf, depth - 1) };
    }
  }

  function sample() {
    const kind = pick(Object.keys(kinds));
    const t = kinds[kind]();
    const text = pick(contexts)(t);
    const asKey = int(0, 4) === 0;
    const leaf = asKey ? { [text]: name() } : text;
    return { kind, token: t, text, value: nest(leaf, int(0, 6)) };
  }

  return { sample };
}

function assertGone(out, token, label) {
  const s = typeof out === 'string' ? out : JSON.stringify(out);
  const plain = [token.raw, token.secret];
  for (const v of plain) assert.ok(!s.includes(v), `${label}: token survived`);
  // No 16-char window of the secret part survives either (also URL-encoded).
  for (let i = 0; i + 16 <= token.secret.length; i += 8) {
    const w = token.secret.slice(i, i + 16);
    assert.ok(!s.includes(w) && !s.includes(encodeURIComponent(w)), `${label}: fragment "${w}" survived in ${s.slice(0, 300)}`);
  }
}

test('fuzz: scrubDeep masks token-shaped values at any depth, under any field name or as a key', () => {
  for (let seed = 1; seed <= 600; seed += 1) {
    const { kind, token, value, text } = makeGen(seed).sample();
    const out = scrubDeep(value);
    assertGone(out, token, `seed ${seed} ${kind} ${text.slice(0, 40)}`);
    const s = JSON.stringify(out);
    assert.ok(s.includes('…') || s.includes(SECRET_MASK), `seed ${seed}: uses the mask style`);
  }
});

test('fuzz: several tokens at once in one TraceStore event (data, note, response body)', () => {
  const t = new TraceStore({ log: () => {} });
  const { runId } = t.create('fuzz');
  for (let seed = 1000; seed < 1150; seed += 1) {
    const g = makeGen(seed);
    const a = g.sample();
    const b = g.sample();
    const c = g.sample();
    const stored = t.add(runId, {
      stepId: `fz-${seed}`, from: 'entra', to: 'daemon', label: 'fuzz', status: 'error',
      data: a.value, note: b.text, response: { status: 400, body: c.value, headers: { [`x-${seed}`]: b.text } },
    });
    for (const s of [a, b, c]) assertGone(stored, s.token, `seed ${seed} ${s.kind}`);
  }
  const all = JSON.stringify(t.get(runId));
  assert.ok(all.length > 0);
});

test('scrubText: named parameters, short secrets and Bearer values are masked', () => {
  const out = scrubText('POST body: client_secret=abc123&code=0123456789abcdef&refresh_token=short-but-secret&x=1 '
    + '{"access_token":"tok-1234567890","password":"hunter2"} Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123');
  for (const leaked of ['abc123', '0123456789abcdef', 'short-but-secret', 'tok-1234567890', 'hunter2', 'abcdefghijklmnopqrstuvwxyz0123']) {
    assert.ok(!out.includes(leaked), leaked);
  }
  assert.ok(out.includes(`client_secret=${SECRET_MASK}`));
  assert.ok(out.includes(`"password":"${SECRET_MASK}"`));
  assert.ok(out.includes('x=1'));
});

test('scrubText keeps ordinary values readable', () => {
  const keep = [
    'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/authorize?client_id=spa&response_type=code',
    'state=Q2hlY2tTdGF0ZVZhbHVlMTIzNDU2Nzg5MGFiY2RlZmdoaWo&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    'AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication.',
    'scp User.Read openid profile; aud api://11111111-2222-3333-4444-555555555555',
    `claims="${Buffer.from('{"access_token":{"acrs":{"essential":true,"value":"c1"}}}').toString('base64url')}"`,
    'token_type=Bearer; expires_in=3599',
    'WWW-Authenticate: Bearer realm="", error="insufficient_claims"',
  ];
  for (const s of keep) assert.equal(scrubText(s), s);
});
