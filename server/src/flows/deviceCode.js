// Device authorization grant (RFC 8628) using the SPA app registration as a public client.
import { GRAPH_SCOPES } from '../config.js';
import { UpstreamError, errorInfo } from '../entra.js';

const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

export async function runDeviceCode(ctx, runId) {
  const { cfg, trace, entra } = ctx;

  const dc = await entra.deviceCodeRequest(runId, {
    stepPrefix: 'dc-code', from: 'device', to: 'entra',
    labelReq: 'Request device code', labelRes: 'Device code + user code',
    form: { client_id: cfg.spaClientId, scope: GRAPH_SCOPES },
    dataRes: (j) => ({ user_code: j.user_code, verification_uri: j.verification_uri, expires_in: j.expires_in, message: j.message }),
  });
  if (!dc.device_code || !dc.user_code) throw new UpstreamError(502, 'invalid_response', 'Device code response is missing fields');

  trace.add(runId, {
    stepId: 'dc-show-code', from: 'device', to: 'user', label: 'Show code to user', determinism: 'human', status: 'ok',
    note: dc.message, data: { user_code: dc.user_code, verification_uri: dc.verification_uri },
  });

  let intervalMs = Math.max(1, Number(dc.interval) || 5) * 1000;
  const deadline = ctx.now() + (Number(dc.expires_in) || 900) * 1000;
  const form = { grant_type: DEVICE_GRANT, client_id: cfg.spaClientId, device_code: dc.device_code };
  const url = cfg.tokenEndpoint;
  const pollReq = (n, label = `Poll token endpoint (#${n})`) => entra.recordFormRequest(runId, {
    stepId: 'dc-poll-req', from: 'device', to: 'entra', label, url, form,
  });

  let token;
  for (let n = 1; ; n += 1) {
    await ctx.sleep(intervalMs);
    if (ctx.now() >= deadline) {
      trace.add(runId, {
        stepId: 'dc-poll-res', from: 'entra', to: 'device', label: 'Device code expired', determinism: 'protocol',
        status: 'error', note: `expired_token: the device code expired after ${dc.expires_in}s without sign-in`,
      });
      throw new UpstreamError(400, 'expired_token', 'The device code expired before the user signed in');
    }
    const r = await entra.postForm(url, form);
    if (r.ok && r.json?.access_token) {
      trace.add(runId, {
        stepId: 'dc-user-signin', from: 'user', to: 'entra', label: 'User signs in', determinism: 'human', status: 'ok',
        note: 'User completed sign-in on a second device',
      });
      pollReq(n, `Poll token endpoint (#${n}, succeeds)`);
      entra.recordResponse(runId, {
        stepId: 'dc-token-res', from: 'entra', to: 'device', label: 'Tokens issued', r,
        note: n === 1 ? 'Tokens issued on the first poll' : `Tokens issued after ${n} polls`,
      });
      token = r.json.access_token;
      break;
    }
    const e = errorInfo(r);
    if (e.error === 'authorization_pending' || e.error === 'slow_down') {
      if (e.error === 'slow_down') intervalMs += 5000;
      if (n === 1 || n % 5 === 0) {
        pollReq(n);
        entra.recordResponse(runId, {
          stepId: 'dc-poll-res', from: 'entra', to: 'device', label: 'Still waiting for the user', r,
          status: 'pending', note: `${e.error}, poll ${n}`,
        });
      }
      continue;
    }
    pollReq(n);
    entra.recordResponse(runId, {
      stepId: 'dc-poll-res', from: 'entra', to: 'device', label: 'Polling failed', r,
      status: 'error', note: `${e.error}: ${e.error_description}`,
    });
    throw new UpstreamError(r.status || 502, e.error, e.error_description);
  }

  const me = await entra.graphGet(runId, 'dc-graph', 'device', 'graph', '/me', token, {
    labelReq: 'GET /me (delegated)', labelRes: 'Signed-in user profile',
  });
  return { me };
}
