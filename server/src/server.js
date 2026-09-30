// AuthFlow Live mode backend: app wiring.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { buildConfig, healthView, loadEnvFile, INDEX_HTML } from './config.js';
import { createEntra } from './entra.js';
import { createValidator } from './validate.js';
import { TraceStore, isValidRunId } from './trace.js';
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
 */
export function createApp(opts = {}) {
  const cfg = opts.cfg ?? buildConfig();
  const trace = opts.trace ?? new TraceStore({ secrets: cfg.secrets, log: opts.log });
  const ctx = {
    cfg,
    trace,
    entra: createEntra({ cfg, trace, fetchImpl: opts.fetchImpl }),
    validator: createValidator({ cfg, jwks: opts.jwks }),
    sleep: opts.sleep ?? ((ms) => new Promise((r) => { setTimeout(r, ms); })),
    now: opts.now ?? (() => Date.now()),
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

  app.get('/api/trace/:runId', (req, res) => {
    const { runId } = req.params;
    if (!isValidRunId(runId)) return res.status(400).json({ error: 'invalid_run_id' });
    return res.json(trace.get(runId, req.query.since));
  });

  // ---- server-run flows ----
  function startServerFlow(flow, enabled, fn) {
    return (req, res) => {
      const runId = req.body?.runId;
      if (!isValidRunId(runId)) return res.status(400).json({ error: 'invalid_run_id', error_description: 'runId must match ^[A-Za-z0-9_-]{8,64}$' });
      const variant = fn.validate ? fn.validate(req.body) : null;
      if (variant === false) return res.status(400).json({ error: 'invalid_request', error_description: 'Invalid variant' });
      if (!enabled(variant)) return res.status(503).json({ error: 'not_configured', error_description: `Flow ${flow} is not configured in .env` });
      if (trace.isRunning(runId)) return res.status(409).json({ error: 'run_in_progress' });
      const run = trace.start(runId, flow);
      run.running = true;
      res.status(202).json({ runId });
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
  mountMcp(app, ctx);

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
