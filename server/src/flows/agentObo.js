// Entra Agent ID: interactive agent acting on behalf of the user (agent OBO).
import { requestParentToken, JWT_BEARER_ASSERTION_TYPE } from './agentAutonomous.js';
import { GRAPH_DEFAULT } from './clientCredentials.js';
import { validationEvent, sendInvalidToken } from './obo.js';
import { readRunIdHeader, errorMessage, upstreamBody } from '../httpUtil.js';

const OBO_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
const MAX_PROMPT = 2000;

export function handleAgentObo(ctx) {
  const { cfg, trace, entra, validator } = ctx;
  return async (req, res) => {
    const runId = readRunIdHeader(req, res);
    if (runId === false) return;
    trace.start(runId, 'agent-obo');

    const v = await validator.validateBearer(req, {
      expectedAudiences: cfg.blueprintAppId ? [cfg.blueprintAppId, `api://${cfg.blueprintAppId}`] : [],
      requiredScope: 'access_as_user',
    });
    const prompt = req.body?.prompt;
    const evt = validationEvent('ao-validate', 'agent', v, 'Agent validates incoming user token');
    if (typeof prompt === 'string') evt.data = { prompt: prompt.slice(0, 200) };
    trace.add(runId, evt);
    if (!v.ok) {
      trace.finish(runId, v.error);
      return sendInvalidToken(res, v);
    }
    if (prompt !== undefined && (typeof prompt !== 'string' || prompt.length > MAX_PROMPT)) {
      trace.finish(runId, 'Invalid prompt');
      return res.status(400).json({ error: 'invalid_request', error_description: `prompt must be a string of at most ${MAX_PROMPT} characters` });
    }
    if (!cfg.flows['agent-obo']) {
      trace.finish(runId, 'Agent OBO flow not configured');
      return res.status(503).json({ error: 'not_configured', error_description: 'BLUEPRINT_APP_ID / BLUEPRINT_CLIENT_SECRET / AGENT_IDENTITY_APP_ID not configured' });
    }

    try {
      const parent = await requestParentToken(ctx, runId, 'ao-parent');
      const obo = await entra.tokenRequest(runId, {
        stepPrefix: 'ao-obo', from: 'agent', to: 'entra',
        labelReq: 'Agent identity OBO (T1 as client assertion, user token as assertion)',
        labelRes: 'Graph token for the agent acting on behalf of the user',
        form: {
          grant_type: OBO_GRANT,
          client_id: cfg.agentIdentityAppId,
          client_assertion_type: JWT_BEARER_ASSERTION_TYPE,
          client_assertion: parent.access_token,
          assertion: v.token,
          requested_token_use: 'on_behalf_of',
          scope: GRAPH_DEFAULT,
        },
      });
      const me = await entra.graphGet(runId, 'ao-graph', 'agent', 'graph', '/me', obo.access_token, {
        labelReq: 'GET /me (agent OBO token)', labelRes: 'User profile',
      });
      const profile = { displayName: me.displayName ?? null, userPrincipalName: me.userPrincipalName ?? null, id: me.id ?? null };
      res.json({
        answer: `Hi ${profile.displayName ?? 'there'}, I (agent identity ${cfg.agentIdentityAppId}) read your profile on your behalf.`,
        me: profile,
      });
      trace.finish(runId);
    } catch (e) {
      res.status(502).json(upstreamBody(e));
      trace.finish(runId, errorMessage(e));
    }
  };
}
