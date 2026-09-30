// Conditional Access What If: POST /identity/conditionalAccess/evaluate with the daemon's app-only token.
import net from 'node:net';
import { AUTH_CONTEXT_RE } from '../config.js';
import { isValidRunId } from '../trace.js';
import { errorMessage, upstreamBody } from '../httpUtil.js';
import { UpstreamError } from '../entra.js';
import { daemonGraphToken } from './daemonToken.js';

export const EVALUATE_PATH = '/identity/conditionalAccess/evaluate';

const SUBJECTS = new Set(['user', 'workload', 'agent']);
const RISK = ['none', 'low', 'medium', 'high'];
const ENUMS = {
  devicePlatform: new Set(['android', 'iOS', 'windows', 'macOS', 'linux', 'all']),
  clientAppType: new Set(['all', 'browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other']),
  signInRiskLevel: new Set(RISK),
  userRiskLevel: new Set(RISK),
  servicePrincipalRiskLevel: new Set(RISK),
  insiderRiskLevel: new Set(['none', 'minor', 'moderate', 'elevated']),
  deviceTrustType: new Set(['AzureAd', 'ServerAd', 'Workplace']),
};
const BOOLEANS = new Set(['deviceCompliant', 'deviceCodeFlow']);
const CONDITION_KEYS = new Set([...Object.keys(ENUMS), ...BOOLEANS, 'country', 'ipAddress']);
const GUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const COUNTRY_RE = /^[A-Z]{2}$/;
const MAX_APPS = 5;

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function onlyKeys(obj, allowed) {
  return Object.keys(obj).find((k) => !allowed.has(k));
}

/**
 * Strict allow-list validation of the What If request body.
 * Returns { ok: true, value: { runId, subject, conditions, context } } or { ok: false, error, error_description }.
 * Optional condition fields may be omitted or null (null means "not set").
 */
export function parseWhatIfRequest(body) {
  const bad = (d) => ({ ok: false, error: 'invalid_request', error_description: d });
  if (!isPlainObject(body)) return bad('Body must be a JSON object');
  const extra = onlyKeys(body, new Set(['runId', 'subject', 'conditions', 'context']));
  if (extra) return bad(`Unknown field ${extra.slice(0, 40)}`);
  if (!isValidRunId(body.runId)) return { ok: false, error: 'invalid_run_id', error_description: 'runId must match ^[A-Za-z0-9_-]{8,64}$' };
  if (!SUBJECTS.has(body.subject)) return bad('subject must be user, workload or agent');

  const rawCond = body.conditions ?? {};
  if (!isPlainObject(rawCond)) return bad('conditions must be an object');
  const extraCond = onlyKeys(rawCond, CONDITION_KEYS);
  if (extraCond) return bad(`Unknown condition ${extraCond.slice(0, 40)}`);
  const conditions = {};
  for (const [k, v] of Object.entries(rawCond)) {
    if (v === null || v === undefined) continue;
    if (ENUMS[k]) {
      if (!ENUMS[k].has(v)) return bad(`${k} must be one of ${[...ENUMS[k]].join(', ')}`);
    } else if (BOOLEANS.has(k)) {
      if (typeof v !== 'boolean') return bad(`${k} must be a boolean`);
    } else if (k === 'country') {
      if (typeof v !== 'string' || !COUNTRY_RE.test(v)) return bad('country must be two uppercase letters');
    } else if (k === 'ipAddress') {
      if (typeof v !== 'string' || v.length > 45 || net.isIP(v) === 0) return bad('ipAddress must be a valid IPv4 or IPv6 address');
    }
    conditions[k] = v;
  }

  const c = body.context;
  if (!isPlainObject(c)) return bad('context is required');
  let context;
  if (c.type === 'app') {
    if (onlyKeys(c, new Set(['type', 'appIds']))) return bad('context has unknown fields');
    if (!Array.isArray(c.appIds) || c.appIds.length === 0 || c.appIds.length > MAX_APPS) return bad(`appIds must be 1 to ${MAX_APPS} GUIDs`);
    if (!c.appIds.every((a) => typeof a === 'string' && GUID_RE.test(a))) return bad('appIds must be GUIDs');
    context = { type: 'app', appIds: [...c.appIds] };
  } else if (c.type === 'authContext') {
    if (onlyKeys(c, new Set(['type', 'value']))) return bad('context has unknown fields');
    if (typeof c.value !== 'string' || !AUTH_CONTEXT_RE.test(c.value)) return bad('authContext value must be c1 to c99');
    context = { type: 'authContext', value: c.value };
  } else {
    return bad('context.type must be app or authContext');
  }
  return { ok: true, value: { runId: body.runId, subject: body.subject, conditions, context } };
}

export function subjectId(cfg, subject) {
  if (subject === 'user') return cfg.demoUserId;
  if (subject === 'workload') return cfg.daemonSpId;
  return cfg.agentIdentitySpId;
}

function compact(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined && v !== null));
}

/** Map the validated request onto the Graph evaluate body. */
export function buildEvaluateBody(cfg, { subject, conditions: c, context }) {
  const signInIdentity = subject === 'user'
    ? { '@odata.type': '#microsoft.graph.userSignIn', userId: cfg.demoUserId }
    : { '@odata.type': '#microsoft.graph.servicePrincipalSignIn', servicePrincipalId: subjectId(cfg, subject) };
  const signInContext = context.type === 'app'
    ? { '@odata.type': '#microsoft.graph.applicationContext', includeApplications: context.appIds }
    : { '@odata.type': '#microsoft.graph.authContext', authenticationContextValue: context.value };
  const hasDevice = (c.deviceCompliant !== undefined && c.deviceCompliant !== null) || !!c.deviceTrustType;
  const signInConditions = compact({
    devicePlatform: c.devicePlatform,
    clientAppType: c.clientAppType,
    country: c.country,
    ipAddress: c.ipAddress,
    signInRiskLevel: c.signInRiskLevel,
    userRiskLevel: c.userRiskLevel,
    servicePrincipalRiskLevel: c.servicePrincipalRiskLevel,
    insiderRiskLevel: c.insiderRiskLevel,
    authenticationFlow: c.deviceCodeFlow ? { transferMethod: 'deviceCodeFlow' } : undefined,
    deviceInfo: hasDevice ? compact({ isCompliant: c.deviceCompliant, trustType: c.deviceTrustType }) : undefined,
  });
  return { signInIdentity, signInContext, signInConditions, appliedPoliciesOnly: false };
}

/** Project Graph's whatIfAnalysisResult list, applying policies first (then by name). */
export function summarisePolicies(json) {
  const list = Array.isArray(json?.value) ? json.value : [];
  return list
    .filter((p) => p && typeof p === 'object')
    .map((p) => ({
      id: p.id ?? null,
      displayName: p.displayName ?? null,
      state: p.state ?? null,
      policyApplies: p.policyApplies === true,
      analysisReasons: p.analysisReasons ?? null,
      grantControls: p.grantControls ?? null,
      sessionControls: p.sessionControls ?? null,
    }))
    .sort((a, b) => (Number(b.policyApplies) - Number(a.policyApplies))
      || String(a.displayName ?? '').localeCompare(String(b.displayName ?? '')));
}

export function handleCaWhatIf(ctx) {
  const { cfg, trace, entra } = ctx;
  return async (req, res) => {
    const parsed = parseWhatIfRequest(req.body);
    if (!parsed.ok) return res.status(400).json({ error: parsed.error, error_description: parsed.error_description });
    const input = parsed.value;
    const { runId } = input;
    if (!cfg.daemonConfigured || !subjectId(cfg, input.subject)) {
      return res.status(503).json({
        error: 'not_configured',
        error_description: 'What If needs the daemon app (DAEMON_CLIENT_ID with a secret or certificate) and DEMO_USER_ID / DAEMON_SP_ID / AGENT_IDENTITY_SP_ID for the chosen subject',
      });
    }
    if (trace.isRunning(runId)) return res.status(409).json({ error: 'run_in_progress' });
    const run = trace.start(runId, 'ca-sim');
    run.running = true;

    try {
      const token = await daemonGraphToken(ctx, runId, 'wi-token', { labelRes: 'App-only Graph token (Policy.Read.ConditionalAccess)' });
      const body = buildEvaluateBody(cfg, input);
      const json = await entra.graphPost(runId, 'wi-eval', 'daemon', 'graph', EVALUATE_PATH, token, body, {
        labelReq: 'POST /identity/conditionalAccess/evaluate', labelRes: 'What If result',
        dataRes: (j) => {
          const all = Array.isArray(j?.value) ? j.value : [];
          return { policies: all.length, applying: all.filter((p) => p?.policyApplies === true).length };
        },
      });
      res.json({ policies: summarisePolicies(json) });
      trace.finish(runId);
    } catch (e) {
      const out = upstreamBody(e);
      if (e instanceof UpstreamError && e.status === 403) {
        out.error_description = `${String(out.error_description ?? '').replace(/\.?\s*$/, '.')} The daemon app needs the Policy.Read.ConditionalAccess application permission.`;
      }
      res.status(502).json(out);
      trace.finish(runId, errorMessage(e));
    }
    return undefined;
  };
}
