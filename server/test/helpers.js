// Shared test helpers (no tests in this file).
import crypto from 'node:crypto';

export function fakeJwt(payload = {}, header = { alg: 'RS256', typ: 'JWT', kid: 'test-kid' }) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const signature = crypto.randomBytes(256).toString('base64url');
  const raw = `${enc(header)}.${enc(payload)}.${signature}`;
  return { raw, signature };
}

export const TENANT = '11111111-2222-3333-4444-555555555555';

export const TEST_ENV = {
  PORT: '5100',
  TENANT_ID: TENANT,
  SPA_CLIENT_ID: 'spa-client-id',
  API_CLIENT_ID: 'api-client-id',
  API_CLIENT_SECRET: 'API-SECRET-value-123456',
  DAEMON_CLIENT_ID: 'daemon-client-id',
  DAEMON_CLIENT_SECRET: 'DAEMON-SECRET-value-123456',
  MCP_CLIENT_ID: 'mcp-client-id',
  MCP_CLIENT_SECRET: 'MCP-SECRET-value-123456',
  BLUEPRINT_APP_ID: 'blueprint-app-id',
  BLUEPRINT_CLIENT_SECRET: 'BLUEPRINT-SECRET-value-123456',
  AGENT_IDENTITY_APP_ID: 'agent-identity-app-id',
};

export function jsonResponse(status, obj, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

export async function listen(app) {
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const { port } = server.address();
  return { server, port, base: `http://127.0.0.1:${port}`, close: () => new Promise((r) => { server.close(r); }) };
}

export async function waitDone(trace, runId, timeoutMs = 5000) {
  const start = Date.now();
  for (;;) {
    const t = trace.get(runId);
    if (t.done) return t;
    if (Date.now() - start > timeoutMs) throw new Error('run did not finish');
    await new Promise((r) => { setTimeout(r, 10); });
  }
}

// Minimal DER encoder for a self-signed RSA test certificate (Node has no X.509 builder).
function der(tag, content) {
  const n = content.length;
  let len;
  if (n < 0x80) len = Buffer.from([n]);
  else {
    const bytes = [];
    for (let v = n; v > 0; v >>= 8) bytes.unshift(v & 0xff);
    len = Buffer.from([0x80 | bytes.length, ...bytes]);
  }
  return Buffer.concat([Buffer.from([tag]), len, content]);
}
const seq = (...parts) => der(0x30, Buffer.concat(parts));
function oid(dotted) {
  const [a, b, ...rest] = dotted.split('.').map(Number);
  const out = [40 * a + b];
  for (const v of rest) {
    const chunk = [v & 0x7f];
    for (let x = v >> 7; x > 0; x >>= 7) chunk.unshift((x & 0x7f) | 0x80);
    out.push(...chunk);
  }
  return der(0x06, Buffer.from(out));
}
function utcTime(d) {
  const s = d.toISOString().replace(/[-:T]/g, '').slice(2, 14);
  return der(0x17, Buffer.from(`${s}Z`));
}

/** Self-signed RSA certificate + PKCS#8 key as PEM strings (test only, generated per run). */
export function selfSignedCert(commonName = 'authflow-test') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const algId = seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00]));
  const name = seq(der(0x31, seq(oid('2.5.4.3'), der(0x0c, Buffer.from(commonName)))));
  const now = Date.now();
  const tbs = seq(
    der(0xa0, der(0x02, Buffer.from([0x02]))),
    der(0x02, Buffer.from([0x01, ...crypto.randomBytes(8)])),
    algId,
    name,
    seq(utcTime(new Date(now - 3600e3)), utcTime(new Date(now + 24 * 3600e3))),
    name,
    publicKey.export({ type: 'spki', format: 'der' }),
  );
  const sig = crypto.sign('sha256', tbs, privateKey);
  const cert = seq(tbs, algId, der(0x03, Buffer.concat([Buffer.from([0x00]), sig])));
  const b64 = cert.toString('base64').match(/.{1,64}/g).join('\n');
  return {
    certPem: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`,
    keyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey,
    certDer: cert,
  };
}
