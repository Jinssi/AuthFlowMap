// Client credentials (daemon, app-only) with a client secret or a certificate assertion.
import fs from 'node:fs/promises';
import { buildClientAssertion } from '../entra.js';
import { tokenEntry } from '../mask.js';

export const GRAPH_DEFAULT = 'https://graph.microsoft.com/.default';
export const USERS_TOP1 = '/users?$top=1&$select=id,displayName';

export async function runClientCredentials(ctx, runId, variant) {
  const { cfg, trace, entra } = ctx;
  const form = { client_id: cfg.daemonClientId, grant_type: 'client_credentials', scope: GRAPH_DEFAULT };

  if (variant === 'certificate') {
    let built;
    try {
      const [certPem, keyPem] = await Promise.all([
        fs.readFile(cfg.daemonCertPath, 'utf8'), fs.readFile(cfg.daemonKeyPath, 'utf8'),
      ]);
      built = buildClientAssertion({ clientId: cfg.daemonClientId, certPem, keyPem, audience: cfg.tokenEndpoint, now: ctx.now() });
    } catch (e) {
      trace.add(runId, {
        stepId: 'cc-build-cred', from: 'daemon', to: 'daemon', label: 'Load credential', determinism: 'protocol',
        status: 'error', note: `Could not build client assertion: ${e?.code ?? e?.message ?? 'error'}`,
      });
      throw new Error('Could not build client assertion from DAEMON_CERT_PATH / DAEMON_KEY_PATH');
    }
    trace.add(runId, {
      stepId: 'cc-build-cred', from: 'daemon', to: 'daemon', label: 'Load credential', determinism: 'protocol', status: 'ok',
      note: 'Signed a short-lived RS256 client assertion with the certificate\'s private key. The key never leaves the server',
      tokens: [tokenEntry('client_assertion', built.assertion)].filter(Boolean),
      data: { credential: 'certificate', x5t: built.x5t, certificateSubject: built.subject, certificateValidTo: built.validTo },
    });
    form.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    form.client_assertion = built.assertion;
  } else {
    trace.add(runId, {
      stepId: 'cc-build-cred', from: 'daemon', to: 'daemon', label: 'Load credential', determinism: 'protocol', status: 'ok',
      note: 'Loaded the client secret from the server environment. The browser never sees it',
      data: { credential: 'secret' },
    });
    form.client_secret = cfg.daemonClientSecret;
  }

  const tok = await entra.tokenRequest(runId, {
    stepPrefix: 'cc-token', from: 'daemon', to: 'entra',
    labelReq: 'Token request (client_credentials)', labelRes: 'App-only access token', form,
  });
  const users = await entra.graphGet(runId, 'cc-graph', 'daemon', 'graph', USERS_TOP1, tok.access_token, {
    labelReq: 'GET /users (app permission)', labelRes: 'Users (app-only)',
  });
  return { users: users.value ?? [] };
}
