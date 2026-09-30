// Configuration: env var names are fixed by the repo-root .env.example.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

export const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const REPO_ROOT = path.resolve(SERVER_DIR, '..');
export const ENV_PATH = path.join(REPO_ROOT, '.env');
export const INDEX_HTML = path.resolve(SERVER_DIR, '..', 'demonstrator', 'index.html');

export const GRAPH_SCOPES = 'openid profile offline_access User.Read';
export const METHODS_SCOPES = 'openid profile offline_access User.Read UserAuthenticationMethod.Read';
export const AUTH_CONTEXT_RE = /^c(?:[1-9]|[1-9][0-9])$/;

/** Load the repo-root .env (explicit path, never cwd-relative). Existing env vars win. */
export function loadEnvFile(envPath = ENV_PATH) {
  if (fs.existsSync(envPath)) dotenv.config({ path: envPath, quiet: true });
}

const ZERO_GUID = /^0{8}-0{4}-0{4}-0{4}-0{12}$/;
const TENANT_RE = /^[A-Za-z0-9.-]{1,100}$/;
const CLIENT_ID_RE = /^[A-Za-z0-9._-]{1,100}$/;

function str(env, key) {
  const v = env[key];
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : null;
}

function id(env, key) {
  const v = str(env, key);
  // Ids are interpolated into URLs / scopes: reject anything odd and the placeholder zero GUID.
  return v && CLIENT_ID_RE.test(v) && !ZERO_GUID.test(v) ? v : null;
}

function resolveFile(p) {
  if (!p) return null;
  return path.isAbsolute(p) ? p : path.resolve(REPO_ROOT, p);
}

function isFile(p) {
  try {
    return !!p && fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

export function buildConfig(env = process.env) {
  const rawPort = Number.parseInt(str(env, 'PORT') ?? '', 10);
  const port = Number.isInteger(rawPort) && rawPort > 0 && rawPort < 65536 ? rawPort : 5100;

  let tenantId = str(env, 'TENANT_ID');
  if (tenantId && (ZERO_GUID.test(tenantId) || !TENANT_RE.test(tenantId))) tenantId = null;

  const cfg = {
    port,
    tenantId,
    spaClientId: id(env, 'SPA_CLIENT_ID'),
    apiClientId: id(env, 'API_CLIENT_ID'),
    apiClientSecret: str(env, 'API_CLIENT_SECRET'),
    daemonClientId: id(env, 'DAEMON_CLIENT_ID'),
    daemonClientSecret: str(env, 'DAEMON_CLIENT_SECRET'),
    daemonCertPath: resolveFile(str(env, 'DAEMON_CERT_PATH')),
    daemonKeyPath: resolveFile(str(env, 'DAEMON_KEY_PATH')),
    webAppClientId: id(env, 'WEBAPP_CLIENT_ID'),
    webAppClientSecret: str(env, 'WEBAPP_CLIENT_SECRET'),
    webAppCertPath: resolveFile(str(env, 'WEBAPP_CERT_PATH')),
    webAppKeyPath: resolveFile(str(env, 'WEBAPP_KEY_PATH')),
    mcpClientId: id(env, 'MCP_CLIENT_ID'),
    mcpClientSecret: str(env, 'MCP_CLIENT_SECRET'),
    blueprintAppId: id(env, 'BLUEPRINT_APP_ID'),
    blueprintClientSecret: str(env, 'BLUEPRINT_CLIENT_SECRET'),
    agentIdentityAppId: id(env, 'AGENT_IDENTITY_APP_ID'),
    demoUserId: id(env, 'DEMO_USER_ID'),
    daemonSpId: id(env, 'DAEMON_SP_ID'),
    agentIdentitySpId: id(env, 'AGENT_IDENTITY_SP_ID'),
    stepUpEnabled: (str(env, 'STEPUP_ENABLED') ?? '').toLowerCase() === 'true',
  };
  const acr = str(env, 'STEPUP_AUTH_CONTEXT');
  cfg.stepUpAuthContext = acr && AUTH_CONTEXT_RE.test(acr) ? acr : 'c1';

  cfg.origin = `http://localhost:${port}`;
  cfg.redirectUri = `${cfg.origin}/auth-callback`;
  cfg.webAppRedirectUri = `${cfg.origin}/webapp/callback`;
  cfg.mcpResource = `${cfg.origin}/mcp`;
  cfg.mcpResourceMetadata = `${cfg.origin}/.well-known/oauth-protected-resource/mcp`;

  const authority = `https://login.microsoftonline.com/${tenantId ?? 'not-configured'}`;
  cfg.authorizeEndpoint = `${authority}/oauth2/v2.0/authorize`;
  cfg.tokenEndpoint = `${authority}/oauth2/v2.0/token`;
  cfg.deviceCodeEndpoint = `${authority}/oauth2/v2.0/devicecode`;
  cfg.jwksUri = `${authority}/discovery/v2.0/keys`;
  cfg.issuerV2 = `${authority}/v2.0`;
  cfg.issuerV1 = `https://sts.windows.net/${tenantId ?? 'not-configured'}/`;

  cfg.scopes = {
    api: `api://${cfg.apiClientId ?? ''}/access_as_user`,
    mcp: `api://${cfg.mcpClientId ?? ''}/mcp.tools`,
    blueprint: `api://${cfg.blueprintAppId ?? ''}/access_as_user`,
    graph: GRAPH_SCOPES,
    methods: METHODS_SCOPES,
  };

  const t = !!tenantId;
  const agent = t && !!cfg.blueprintAppId && !!cfg.blueprintClientSecret && !!cfg.agentIdentityAppId;
  const daemonSecret = t && !!cfg.daemonClientId && !!cfg.daemonClientSecret;
  const daemonCert = t && !!cfg.daemonClientId && isFile(cfg.daemonCertPath) && isFile(cfg.daemonKeyPath);
  const daemon = daemonSecret || daemonCert;
  const webAppSecret = t && !!cfg.webAppClientId && !!cfg.webAppClientSecret;
  const webAppCert = t && !!cfg.webAppClientId && isFile(cfg.webAppCertPath) && isFile(cfg.webAppKeyPath);
  cfg.flows = {
    'auth-code-pkce': t && !!cfg.spaClientId,
    obo: t && !!cfg.spaClientId && !!cfg.apiClientId && !!cfg.apiClientSecret,
    'client-credentials': {
      secret: daemonSecret,
      certificate: daemonCert,
    },
    'device-code': t && !!cfg.spaClientId,
    'agent-autonomous': agent,
    'agent-obo': agent && !!cfg.spaClientId,
    'mcp-auth': t && !!cfg.spaClientId && !!cfg.mcpClientId,
    'mcp-obo': t && !!cfg.spaClientId && !!cfg.mcpClientId && !!cfg.mcpClientSecret,
    'step-up': t && !!cfg.apiClientId && !!cfg.apiClientSecret && cfg.stepUpEnabled,
    'ca-sim': daemon && !!cfg.demoUserId,
    aitm: t && !!cfg.spaClientId,
    'device-sso': t && !!cfg.spaClientId,
    'id-protection': daemon,
    'web-app': {
      secret: webAppSecret,
      certificate: webAppCert,
    },
  };
  cfg.daemonConfigured = daemon;

  // Values that must never appear in any trace event or response (safety net for the trace store).
  cfg.secrets = [cfg.apiClientSecret, cfg.daemonClientSecret, cfg.mcpClientSecret, cfg.blueprintClientSecret, cfg.webAppClientSecret]
    .filter((s) => typeof s === 'string' && s.length >= 6);

  return cfg;
}

/** Public, secret-free view for GET /api/health. */
export function healthView(cfg) {
  const f = cfg.flows;
  const live = Object.values(f).some((v) => (typeof v === 'object' ? v.secret || v.certificate : v));
  return {
    ok: true,
    live,
    tenantId: cfg.tenantId,
    redirectUri: cfg.redirectUri,
    spaClientId: cfg.spaClientId,
    scopes: { ...cfg.scopes },
    flows: {
      ...f,
      'client-credentials': { ...f['client-credentials'] },
      'web-app': { ...f['web-app'] },
    },
    ids: {
      apiClientId: cfg.apiClientId,
      mcpClientId: cfg.mcpClientId,
      daemonClientId: cfg.daemonClientId,
      blueprintAppId: cfg.blueprintAppId,
      agentIdentityAppId: cfg.agentIdentityAppId,
      webAppClientId: cfg.webAppClientId,
    },
    stepUpAuthContext: cfg.stepUpAuthContext,
    whatIfSubjects: {
      user: !!cfg.demoUserId,
      workload: !!cfg.daemonSpId,
      agent: !!cfg.agentIdentitySpId,
    },
  };
}
