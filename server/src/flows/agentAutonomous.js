// Entra Agent ID: autonomous agent (app-only) via blueprint -> agent identity token exchange.
import { GRAPH_DEFAULT, USERS_TOP1 } from './clientCredentials.js';

export const JWT_BEARER_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/** Step 1 (shared with agent OBO): blueprint gets an exchange token (T1) for the agent identity. */
export function requestParentToken(ctx, runId, stepPrefix) {
  const { cfg, entra } = ctx;
  return entra.tokenRequest(runId, {
    stepPrefix, from: 'agent', to: 'entra',
    labelReq: 'Blueprint requests exchange token (fmi_path = agent identity)',
    labelRes: 'Blueprint exchange token (T1)',
    form: {
      client_id: cfg.blueprintAppId,
      client_secret: cfg.blueprintClientSecret,
      grant_type: 'client_credentials',
      scope: 'api://AzureADTokenExchange/.default',
      fmi_path: cfg.agentIdentityAppId,
    },
  });
}

export async function runAgentAutonomous(ctx, runId) {
  const { cfg, entra } = ctx;
  const parent = await requestParentToken(ctx, runId, 'aa-parent');
  const tok = await entra.tokenRequest(runId, {
    stepPrefix: 'aa-agent', from: 'agent', to: 'entra',
    labelReq: 'Agent identity token request (T1 as client assertion)',
    labelRes: 'Agent identity access token (app-only)',
    form: {
      client_id: cfg.agentIdentityAppId,
      grant_type: 'client_credentials',
      client_assertion_type: JWT_BEARER_ASSERTION_TYPE,
      client_assertion: parent.access_token,
      scope: GRAPH_DEFAULT,
    },
  });
  const users = await entra.graphGet(runId, 'aa-graph', 'agent', 'graph', USERS_TOP1, tok.access_token, {
    labelReq: 'GET /users (as agent identity)', labelRes: 'Users (agent identity)',
  });
  return { users: users.value ?? [] };
}
