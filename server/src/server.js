// AuthFlow Live mode backend: app wiring.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { buildConfig, healthView, loadEnvFile, INDEX_HTML } from './config.js';
import { createEntra } from './entra.js';
import { createValidator } from './validate.js';
import { TraceStore } from './trace.js';
import { RateLimiter, DEFAULT_LIMITS } from './limits.js';
import { errorMessage } from './httpUtil.js';
import { runClientCredentials } from './flows/clientCredentials.js';
import { runDeviceCode } from './flows/deviceCode.js';
import { runAgentAutonomous } from './flows/agentAutonomous.js';
import { handleOboMe } from './flows/obo.js';
import { handleAgentObo } from './flows/agentObo.js';
import { handleStepUpApprove } from './flows/stepUp.js';
import { handleCaWhatIf } from './flows/caWhatIf.js';
import { runIdProtection } from './flows/idProtection.js';
import { mountWebApp } from './flows/webApp.js';
import { mountMcp } from './mcp/server.js';

const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '[::1]']);
// Flows whose requests come from the browser (X-Run-Id header). Their runs start with POST /api/runs.
export const BROWSER_TRACE_FLOWS = new Set(['obo', 'step-up', 'agent-obo', 'mcp', 'web-app']);

function callbackPage(nonce) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>AuthFlow sign-in callback</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;padding:2rem"><p>You can close this window.</p>
<script nonce="${nonce}">
(function () {
  var s = new URLSearchParams(location.search);
  var h = new URLSearchParams(location.hash.replace(/^#/, ''));
  function p(k) { return h.get(k) || s.get(k) || null; }
  var msg = { type: 'authflow-callback', code: p('code'), state: p('state'), error: p('error'), error_description: p('error_description') };
  try { history.replaceState(null, '', location.pathname); } catch (e) {}
  if (window.opener) { window.opener.postMessage(msg, location.origin); window.close(); }
})();
</script></body></html>`;
}

/**
 * @param {object} [opts]
 * @param {object} [opts.cfg] config (defaults to buildConfig(process.env))
 * @param {Function} [opts.fetchImpl] fetch used for Entra/Graph (tests inject a mock)
 * @param {Function} [opts.jwks] jose key resolver (tests inject a local JWKS)
 * @param {Function} [opts.sleep] device code polling sleep
 * @param {Function} [opts.log] one-line logger
 * @param {object} [opts.limits] overrides for DEFAULT_LIMITS (runsPerMinute, maxConcurrentFlows)
 */
export function createApp(opts = {}) {
  const cfg = opts.cfg ?? buildConfig();
  const trace = opts.trace ?? new TraceStore({ secrets: cfg.secrets, log: opts.log });
  const limits = { ...DEFAULT_LIMITS, ...(opts.limits ?? {}) };
  const ctx = {
    cfg,
    trace,
    entra: createEntra({ cfg, trace, fetchImpl: opts.fetchImpl }),
    validator: createValidator({ cfg, jwks: opts.jwks }),
    sleep: opts.sleep ?? ((ms) => new Promise((r) => { setTimeout(r, ms); })),
    now: opts.now ?? (() => Date.now()),
  };
  const runLimiter = new RateLimiter({ max: limits.runsPerMinute, now: ctx.now });

  /**
   * Admit a new run under the caps: run starts per minute and, for flows the server runs in the
   * background, concurrent running flows. Sends 429 with Retry-After and returns false when over.
   */
  ctx.admitRun = (res, { serverFlow = false } = {}) => {
    if (serverFlow && trace.runningCount() >= limits.maxConcurrentFlows) {
      res.set('Retry-After', String(limits.concurrentRetryAfterSec));
      res.status(429).json({ error: 'too_many_requests', error_description: `At most ${limits.maxConcurrentFlows} server flows can run at the same time` });
      return false;
    }
    const wait = runLimiter.take();
    if (wait > 0) {
      res.set('Retry-After', String(wait));
      res.status(429).json({ error: 'too_many_requests', error_description: `At most ${limits.runsPerMinute} runs can start per minute` });
      return false;
    }
    return true;
  };

  const app = express();
  app.locals.ctx = ctx;
  app.disable('x-powered-by');
  app.set('etag', false);

  // Security headers. Deliberately no CORS headers: same-origin only.
  app.use((req, res, next) => {
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'no-referrer');
    if (req.path.startsWith('/api/') || req.path === '/mcp') res.set('Cache-Control', 'no-store');
    next();
  });

  // DNS-rebinding guard: only accept loopback Host headers on the port we actually listen on.
  app.use((req, res, next) => {
    const host = String(req.headers.host ?? '').toLowerCase();
    const m = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(host);
    const port = String(req.socket.localPort ?? '');
    if (!m || !LOCAL_HOSTNAMES.has(m[1]) || (m[2] ?? '80') !== port) {
      return res.status(403).type('text/plain').send('Forbidden host');
    }
    // Cross-site request guard for state-changing requests (browsers always send Origin on POST).
    const origin = req.headers.origin;
    if (req.method !== 'GET' && req.method !== 'HEAD' && origin !== undefined) {
      let ok = false;
      try {
        const u = new URL(origin);
        ok = u.protocol === 'http:' && LOCAL_HOSTNAMES.has(u.hostname) && u.port === port;
      } catch {
        ok = false;
      }
      if (!ok) return res.status(403).json({ error: 'forbidden_origin' });
    }
    return next();
  });

  app.use(express.json({ limit: '64kb' }));

  // ---- static ----
  app.get('/', (req, res) => {
    if (!fs.existsSync(INDEX_HTML)) return res.status(404).type('text/plain').send('Run: node demonstrator/build.mjs');
    return res.sendFile(INDEX_HTML);
  });

  app.get('/auth-callback', (req, res) => {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.set('Content-Security-Policy', `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'`);
    res.set('Cache-Control', 'no-store');
    res.type('html').send(callbackPage(nonce));
  });

  // ---- config / trace ----
  app.get('/api/health', (req, res) => res.json(healthView(cfg)));

  // Start a run for a browser-initiated flow. The server picks the run ID and the read key.
  app.post('/api/runs', (req, res) => {
    const flow = req.body?.flow;
    if (typeof flow !== 'string' || !BROWSER_TRACE_FLOWS.has(flow)) {
      return res.status(400).json({ error: 'invalid_request', error_description: `flow must be one of ${[...BROWSER_TRACE_FLOWS].join(', ')}` });
    }
    if (!ctx.admitRun(res)) return undefined;
    res.set('Cache-Control', 'no-store');
    return res.status(201).json(trace.create(flow));
  });

  // Reading a trace needs the run's key. Unknown run and wrong key look the same (404).
  app.get('/api/trace/:runId', (req, res) => {
    res.set('Cache-Control', 'no-store');
    const result = trace.read(req.params.runId, req.get('x-trace-key'), req.query.since);
    if (!result) return res.status(404).json({ error: 'not_found' });
    return res.json(result);
  });

  // ---- server-run flows ----
  function startServerFlow(flow, enabled, fn) {
    return (req, res) => {
      // A client-supplied runId is ignored: the server always issues a fresh one.
      const variant = fn.validate ? fn.validate(req.body) : null;
      if (variant === false) return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid variant' });
      if (!enabled(variant)) return res.status(503).json({ error: 'not_configured', error_description: `Flow ${flow} is not configured in .env` });
      if (!ctx.admitRun(res, { serverFlow: true })) return undefined;
      const { runId, traceKey } = trace.create(flow);
      trace.start(runId, flow).running = true;
      res.status(202).json({ runId, traceKey });
      Promise.resolve()
        .then(() => fn(ctx, runId, variant))
        .then(() => trace.finish(runId))
        .catch((e) => trace.finish(runId, errorMessage(e)));
      return undefined;
    };
  }

  const cc = (c, runId, variant) => runClientCredentials(c, runId, variant);
  cc.validate = (body) => {
    const v = body?.variant ?? 'secret';
    return v === 'secret' || v === 'certificate' ? v : false;
  };
  app.post('/api/live/client-credentials', startServerFlow('client-credentials', (v) => cfg.flows['client-credentials'][v], cc));
  app.post('/api/live/device-code', startServerFlow('device-code', () => cfg.flows['device-code'], runDeviceCode));
  app.post('/api/live/agent-autonomous', startServerFlow('agent-autonomous', () => cfg.flows['agent-autonomous'], runAgentAutonomous));
  app.post('/api/live/id-protection', startServerFlow('id-protection', () => cfg.flows['id-protection'], runIdProtection));
  app.post('/api/live/ca-whatif', handleCaWhatIf(ctx));

  // ---- browser-initiated ----
  app.get('/api/obo/me', handleOboMe(ctx));
  app.post('/api/stepup/approve', handleStepUpApprove(ctx));
  app.post('/api/agent/obo', handleAgentObo(ctx));
  app.locals.mcp = mountMcp(app, ctx);

  // ---- confidential web app (server-side session) ----
  app.locals.webApp = mountWebApp(app, ctx);

  // ---- fallbacks ----
  app.use((req, res) => res.status(404).json({ error: 'not_found' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err?.type === 'entity.parse.failed' ? 400 : err?.type === 'entity.too.large' ? 413 : 500;
    if (req.path === '/mcp' && status === 400) {
      return res.status(400).json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    }
    if (status === 500) console.log(`flow server step unhandled error`);
    return res.status(status).json({ error: status === 400 ? 'invalid_json' : status === 413 ? 'payload_too_large' : 'server_error' });
  });

  return app;
}

function isMain() {
  if (!process.argv[1]) return false;
  const a = path.resolve(process.argv[1]).toLowerCase();
  const b = fileURLToPath(import.meta.url).toLowerCase();
  return a === b;
}

if (isMain()) {
  loadEnvFile();
  const cfg = buildConfig();
  const app = createApp({ cfg });
  app.listen(cfg.port, '127.0.0.1', () => {
    console.log(`AuthFlow live server on http://localhost:${cfg.port} (live=${healthView(cfg).live})`);
  });
}
