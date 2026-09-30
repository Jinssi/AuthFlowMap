// Step-up with a Conditional Access authentication context: the API demands an acrs claim.
import { validationEvent, sendInvalidToken } from './obo.js';
import { readRunIdHeader } from '../httpUtil.js';

const MAX_PAYMENT_ID = 64;

/** acrs claim as a string array (the claim may be an array or a single string). */
export function acrsList(payload) {
  const v = payload?.acrs;
  if (Array.isArray(v)) return v.filter((x) => typeof x === 'string');
  if (typeof v === 'string' && v !== '') return v.split(/[\s,]+/).filter(Boolean);
  return [];
}

/** Claims challenge JSON for an authentication context value. */
export function claimsChallenge(authContext) {
  return JSON.stringify({ access_token: { acrs: { essential: true, value: authContext } } });
}

export function stepUpWwwAuthenticate(tenantId, claims) {
  const b64 = Buffer.from(claims, 'utf8').toString('base64');
  return `Bearer realm="", authorization_uri="https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/authorize", error="insufficient_claims", claims="${b64}"`;
}

export function handleStepUpApprove(ctx) {
  const { cfg, trace, validator } = ctx;
  return async (req, res) => {
    const runId = readRunIdHeader(req, res);
    if (runId === false) return;
    trace.start(runId, 'step-up');
    const acrCtx = cfg.stepUpAuthContext;

    const v = await validator.validateBearer(req, {
      expectedAudiences: cfg.apiClientId ? [cfg.apiClientId, `api://${cfg.apiClientId}`] : [],
      requiredScope: 'access_as_user',
    });
    const hasAcrsClaim = v.payload && v.payload.acrs !== undefined && v.payload.acrs !== null;
    const acrs = acrsList(v.payload);
    const acrsOk = acrs.includes(acrCtx);
    const acrsCheck = {
      name: `acrs contains ${acrCtx}`,
      ok: acrsOk,
      detail: hasAcrsClaim ? (Array.isArray(v.payload.acrs) ? v.payload.acrs.join(', ') : String(v.payload.acrs)) : 'no acrs claim',
    };
    const evt = validationEvent('su-validate', 'api', { ...v, checks: [...v.checks, acrsCheck] }, 'Validate token and acrs');
    if (v.ok && !acrsOk) {
      evt.status = 'error';
      evt.note = `Token valid, but acrs does not contain ${acrCtx}`;
    }
    trace.add(runId, evt);
    if (!v.ok) {
      trace.finish(runId, v.error);
      return sendInvalidToken(res, v);
    }

    const { paymentId, amount } = req.body ?? {};
    if (typeof paymentId !== 'string' || paymentId.length === 0 || paymentId.length > MAX_PAYMENT_ID
      || typeof amount !== 'number' || !Number.isFinite(amount)) {
      trace.finish(runId, 'Invalid request');
      return res.status(400).json({
        error: 'invalid_request',
        error_description: `paymentId must be a string of 1 to ${MAX_PAYMENT_ID} characters and amount a finite number`,
      });
    }
    if (!cfg.flows['step-up']) {
      trace.finish(runId, 'Step-up flow not configured');
      return res.status(503).json({ error: 'not_configured', error_description: 'STEPUP_ENABLED / API_CLIENT_ID / API_CLIENT_SECRET not configured' });
    }

    if (!acrsOk) {
      const claims = claimsChallenge(acrCtx);
      const www = stepUpWwwAuthenticate(cfg.tenantId, claims);
      const body = { error: 'insufficient_claims', error_description: 'This action needs step-up authentication', claims };
      trace.add(runId, {
        stepId: 'su-challenge', from: 'api', to: 'browser', label: '401 insufficient_claims', determinism: 'policy', status: 'ok',
        response: { status: 401, statusText: 'Unauthorized', headers: { 'www-authenticate': www }, body },
        note: `Claims challenge: sign in again satisfying authentication context ${acrCtx}`,
        data: { claims },
      });
      res.set('WWW-Authenticate', www);
      res.status(401).json(body);
      trace.finish(runId);
      return undefined;
    }

    trace.add(runId, {
      stepId: 'su-approve', from: 'api', to: 'api', label: 'Payment approved', determinism: 'protocol', status: 'ok',
      data: { paymentId, amount },
    });
    res.json({
      approved: true, paymentId, amount, approvedBy: v.payload.name ?? v.payload.preferred_username ?? null, acrs,
    });
    trace.finish(runId);
    return undefined;
  };
}
