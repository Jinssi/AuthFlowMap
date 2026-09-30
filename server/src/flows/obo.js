// Classic On-Behalf-Of: the middle-tier API validates the user's token and exchanges it for Graph.
import { tokenEntry } from '../mask.js';
import { readRunIdHeader, errorMessage, upstreamBody, q } from '../httpUtil.js';

const OBO_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';

export function validationEvent(stepId, actor, v, label = 'Validate incoming access token') {
  return {
    stepId, from: actor, to: actor, label, determinism: 'protocol', status: v.ok ? 'ok' : 'error',
    checks: v.checks, tokens: v.token ? [tokenEntry('access_token', v.token)].filter(Boolean) : undefined,
    note: v.ok ? 'All checks passed' : v.error,
  };
}

export function sendInvalidToken(res, v) {
  res.set('WWW-Authenticate', `Bearer error="invalid_token", error_description="${q(v.error)}"`);
  res.status(401).json({ error: 'invalid_token', error_description: v.error, checks: v.checks });
}

export function handleOboMe(ctx) {
  const { cfg, trace, entra, validator } = ctx;
  return async (req, res) => {
    const runId = readRunIdHeader(req, res);
    if (runId === false) return;
    trace.start(runId, 'obo');

    const v = await validator.validateBearer(req, {
      expectedAudiences: cfg.apiClientId ? [cfg.apiClientId, `api://${cfg.apiClientId}`] : [],
      requiredScope: 'access_as_user',
    });
    trace.add(runId, validationEvent('obo-validate', 'api', v));
    if (!v.ok) {
      trace.finish(runId, v.error);
      return sendInvalidToken(res, v);
    }
    if (!cfg.flows.obo) {
      trace.finish(runId, 'OBO flow not configured');
      return res.status(503).json({ error: 'not_configured', error_description: 'API_CLIENT_ID / API_CLIENT_SECRET not configured' });
    }

    try {
      const obo = await entra.tokenRequest(runId, {
        stepPrefix: 'obo-exchange', from: 'api', to: 'entra',
        labelReq: 'OBO token exchange (user token as assertion)', labelRes: 'Graph token on behalf of the user',
        form: {
          grant_type: OBO_GRANT,
          client_id: cfg.apiClientId,
          client_secret: cfg.apiClientSecret,
          assertion: v.token,
          scope: 'https://graph.microsoft.com/User.Read',
          requested_token_use: 'on_behalf_of',
        },
      });
      const me = await entra.graphGet(runId, 'obo-graph', 'api', 'graph', '/me', obo.access_token, {
        labelReq: 'GET /me (OBO token)', labelRes: 'User profile',
      });
      res.json({ me: { displayName: me.displayName ?? null, userPrincipalName: me.userPrincipalName ?? null, id: me.id ?? null } });
      trace.finish(runId);
    } catch (e) {
      res.status(502).json(upstreamBody(e));
      trace.finish(runId, errorMessage(e));
    }
  };
}
