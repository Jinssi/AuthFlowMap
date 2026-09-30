// App-only Graph token for the daemon app (client secret preferred, certificate if only that is configured).
import fs from 'node:fs/promises';
import { buildClientAssertion } from '../entra.js';
import { GRAPH_DEFAULT } from './clientCredentials.js';
import { JWT_BEARER_ASSERTION_TYPE } from './agentAutonomous.js';

/** Returns the raw access token. Records `${stepPrefix}-req` / `${stepPrefix}-res` (daemon -> entra). */
export async function daemonGraphToken(ctx, runId, stepPrefix, { labelReq, labelRes } = {}) {
  const { cfg, entra } = ctx;
  const form = { client_id: cfg.daemonClientId, grant_type: 'client_credentials', scope: GRAPH_DEFAULT };
  let noteReq;
  if (cfg.flows['client-credentials'].secret) {
    form.client_secret = cfg.daemonClientSecret;
    noteReq = 'Daemon authenticates with its client secret';
  } else {
    let built;
    try {
      const [certPem, keyPem] = await Promise.all([
        fs.readFile(cfg.daemonCertPath, 'utf8'), fs.readFile(cfg.daemonKeyPath, 'utf8'),
      ]);
      built = buildClientAssertion({ clientId: cfg.daemonClientId, certPem, keyPem, audience: cfg.tokenEndpoint, now: ctx.now() });
    } catch {
      throw new Error('Could not build client assertion from DAEMON_CERT_PATH / DAEMON_KEY_PATH');
    }
    form.client_assertion_type = JWT_BEARER_ASSERTION_TYPE;
    form.client_assertion = built.assertion;
    noteReq = 'Daemon authenticates with a certificate-signed client assertion';
  }
  const tok = await entra.tokenRequest(runId, {
    stepPrefix, from: 'daemon', to: 'entra',
    labelReq: labelReq ?? 'Token request (client_credentials)', labelRes: labelRes ?? 'App-only access token',
    form, noteReq,
  });
  return tok.access_token;
}
