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
