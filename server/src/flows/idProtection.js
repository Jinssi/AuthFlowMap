// Identity Protection: read recent risk detections and risky users with the daemon's app-only token.
import { UpstreamError } from '../entra.js';
import { maskUpnsDeep } from '../mask.js';
import { daemonGraphToken } from './daemonToken.js';

export const RISK_DETECTIONS = '/identityProtection/riskDetections?$top=5&$orderby=detectedDateTime%20desc';
export const RISKY_USERS = '/identityProtection/riskyUsers?$top=5';
export const P2_NOTE = 'Needs Entra ID P2 and IdentityRiskEvent.Read.All / IdentityRiskyUser.Read.All';

/** Returns the Graph list, or null after a 403 (already recorded as an error event). */
async function tolerant403(fn) {
  try {
    const j = await fn();
    return Array.isArray(j?.value) ? j.value : [];
  } catch (e) {
    if (e instanceof UpstreamError && e.status === 403) return null;
    throw e;
  }
}

export async function runIdProtection(ctx, runId) {
  const { trace, entra } = ctx;
  const token = await daemonGraphToken(ctx, runId, 'ip-token', { labelRes: 'App-only Graph token (Identity Protection)' });
  const detections = await tolerant403(() => entra.graphGet(runId, 'ip-det', 'daemon', 'graph', RISK_DETECTIONS, token, {
    labelReq: 'GET /identityProtection/riskDetections', labelRes: 'Risk detections', maskBody: maskUpnsDeep,
  }));
  const riskyUsers = await tolerant403(() => entra.graphGet(runId, 'ip-users', 'daemon', 'graph', RISKY_USERS, token, {
    labelReq: 'GET /identityProtection/riskyUsers', labelRes: 'Risky users', maskBody: maskUpnsDeep,
  }));
  const types = [...new Set((detections ?? []).map((d) => d?.riskEventType).filter((t) => typeof t === 'string'))];
  trace.add(runId, {
    stepId: 'ip-summary', from: 'daemon', to: 'daemon', label: 'Summarise risk', determinism: 'policy', status: 'ok',
    note: detections === null || riskyUsers === null ? P2_NOTE : undefined,
    data: {
      detections: detections === null ? null : detections.length,
      riskyUsers: riskyUsers === null ? null : riskyUsers.length,
      topRiskEventTypes: types,
    },
  });
}
