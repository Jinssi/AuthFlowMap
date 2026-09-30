// Confidential-client web app: the server proves its own identity (client secret or certificate)
// and the user's identity (authorization code + PKCE). Tokens stay on the server; the browser
// only ever gets a session cookie.
import crypto from 'node:crypto';
import { GRAPH_SCOPES } from '../config.js';
import { loadClientAssertion } from '../entra.js';
import { isValidRunId } from '../trace.js';
import { tokenEntry } from '../mask.js';
import { errorMessage } from '../httpUtil.js';

const PENDING_TTL_MS = 10 * 60 * 1000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const MAX_ENTRIES = 100;
const ME_PATH = '/me?$select=displayName,userPrincipalName,id';
const JWT_BEARER = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const COOKIE_ATTRS = 'HttpOnly; SameSite=Lax; Path=/webapp';

const b64url = (n) => crypto.randomBytes(n).toString('base64url');

export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

/** Value of a cookie from the raw Cookie header, or null. */
export function readCookie(req, name) {
  const raw = req.headers?.cookie;
  if (typeof raw !== 'string') return null;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function qstr(v) {
  return typeof v === 'string' && v !== '' ? v : null;
}

const maskState = (state) => `${state.slice(0, 8)}…`;
const maskCode = (code) => `${code.slice(0, 6)}…[redacted]`;

/** PKCE pair: 43-char base64url verifier and its S256 challenge. */
export function pkcePair() {
  const verifier = b64url(32);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function page(title, bodyHtml, scriptNonce, script) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>${escapeHtml(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1"></head>
<body style="font-family:system-ui,sans-serif;padding:2rem">${bodyHtml}${script ? `
<script nonce="${scriptNonce}">
${script}
</script>` : ''}</body></html>`;
}

function sendHtml(res, status, html, scriptNonce) {
  const scriptSrc = scriptNonce ? `'nonce-${scriptNonce}'` : "'none'";
  res.set('Content-Security-Policy', `default-src 'none'; script-src ${scriptSrc}; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`);
  res.set('Cache-Control', 'no-store');
  res.status(status).type('html').send(html);
}

function sendError(res, status, message) {
  sendHtml(res, status, page('AuthFlow demo web app', `<h1>Sign-in failed</h1><p>${escapeHtml(message)}</p><p>You can close this window.</p>`));
}

/**
 * Token response checks for the authorization_code redemption. Entra checks client authentication
 * first, then PKCE, then the code binding; on failure later checks are not evaluated.
 */
function tokenChecks(variant) {
  return (json, ok, err) => {
    const names = [
      `App authenticated with ${variant === 'secret' ? 'its client secret' : 'a certificate-signed assertion'}`,
      'PKCE verifier matched the challenge',
      'Code bound to this client_id and redirect_uri',
    ];
    if (ok) return names.map((name) => ({ name, ok: true }));
    const text = `${err?.error ?? ''} ${err?.error_description ?? ''}`;
    let failed = 2;
    if (/invalid_client|AADSTS7000215|AADSTS700027|AADSTS7000222|AADSTS700023|AADSTS7000218/.test(text)) failed = 0;
    else if (/AADSTS50148|AADSTS501481|code_verifier|PKCE/i.test(text)) failed = 1;
    return names.map((name, i) => (i < failed
      ? { name, ok: true }
      : { name, ok: false, detail: i === failed ? String(err?.error ?? 'error') : 'Not evaluated' }));
  };
}

export function mountWebApp(app, ctx) {
  const { cfg, trace, entra, validator } = ctx;
  const pending = new Map(); // state -> { runId, variant, nonce, verifier, bindingId, createdAt }
  const sessions = new Map(); // session id -> { tokens, name, createdAt }

  function sweep(map, ttl) {
    const cutoff = ctx.now() - ttl;
    for (const [k, v] of map) if (v.createdAt < cutoff) map.delete(k);
  }
  function putCapped(map, key, value) {
    while (map.size >= MAX_ENTRIES) map.delete(map.keys().next().value);
    map.set(key, value);
  }

  app.use('/webapp', (req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  // ---- 1. login: state, nonce, PKCE, binding cookie, 302 to /authorize ----
  app.get('/webapp/login', (req, res) => {
    const { runId } = req.query;
    if (!isValidRunId(runId)) {
      return res.status(400).json({ error: 'invalid_run_id', error_description: 'runId must match ^[A-Za-z0-9_-]{8,64}$' });
    }
    const variant = req.query.variant ?? 'secret';
    if (variant !== 'secret' && variant !== 'certificate') {
      return res.status(400).json({ error: 'invalid_request', error_description: 'variant must be secret or certificate' });
    }
    if (!cfg.flows['web-app'][variant]) {
      return res.status(503).json({ error: 'not_configured', error_description: 'Flow web-app is not configured in .env' });
    }

    const state = b64url(32);
    const nonce = crypto.randomUUID();
    const { verifier, challenge } = pkcePair();
    const bindingId = b64url(32);
    sweep(pending, PENDING_TTL_MS);
    putCapped(pending, state, { runId, variant, nonce, verifier, bindingId, createdAt: ctx.now() });

    const params = new URLSearchParams({
      client_id: cfg.webAppClientId,
      response_type: 'code',
      redirect_uri: cfg.webAppRedirectUri,
      response_mode: 'query',
      scope: GRAPH_SCOPES,
      state,
      nonce,
      code_challenge: challenge,
      code_challenge_method: 'S256',
      prompt: 'select_account',
    });
    const authorizeUrl = `${cfg.authorizeEndpoint}?${params}`;

    trace.start(runId, 'web-app');
    trace.add(runId, {
      stepId: 'wa-req', from: 'browser', to: 'webapp', label: 'GET /webapp/login', determinism: 'protocol', status: 'ok',
      request: { method: 'GET', url: `${cfg.origin}/webapp/login?runId=${runId}&variant=${variant}` },
      note: `Sign-in to the demo web app with the ${variant === 'secret' ? 'client secret' : 'certificate'} variant.`,
    });
    trace.add(runId, {
      stepId: 'wa-pkce', from: 'webapp', to: 'webapp', label: 'State, nonce and PKCE', determinism: 'protocol', status: 'ok',
      data: { state: maskState(state), nonce, code_challenge: challenge, method: 'S256', code_verifier: 'kept on the server' },
      note: 'The server remembers state, nonce and the PKCE verifier for 10 minutes. Each one can be used once.',
    });
    trace.add(runId, {
      stepId: 'wa-redirect', from: 'webapp', to: 'browser', label: '302 to /authorize', determinism: 'protocol', status: 'ok',
      response: {
        status: 302, statusText: 'Found',
        headers: { location: authorizeUrl, 'set-cookie': 'wa_bind=…[masked]; HttpOnly; SameSite=Lax' },
      },
      note: 'The wa_bind cookie ties the callback to this browser.',
    });
    trace.add(runId, {
      stepId: 'wa-authz', from: 'browser', to: 'entra', label: 'GET /authorize', determinism: 'protocol', status: 'ok',
      request: { method: 'GET', url: authorizeUrl },
      note: 'The user signs in at Entra ID.',
    });

    res.append('Set-Cookie', `wa_bind=${bindingId}; ${COOKIE_ATTRS}; Max-Age=600`);
    res.redirect(302, authorizeUrl);
    return undefined;
  });

  // ---- 2. callback: check state + binding, redeem the code, validate the ID token, session ----
  app.get('/webapp/callback', async (req, res) => {
    const state = qstr(req.query.state);
    const entry = state ? pending.get(state) : undefined;
    if (!entry) return sendError(res, 400, 'This sign-in response is unknown, expired or already used.');
    pending.delete(state); // single use, before any await
    const { runId, variant } = entry;

    const code = qstr(req.query.code);
    const err = qstr(req.query.error);
    const errDesc = qstr(req.query.error_description);
    const entraError = err ? `${err}: ${(errDesc ?? '').split(/\r?\n/)[0] || 'no description'}` : (code ? null : 'invalid_request: no code in the callback');

    const query = err
      ? `error=${encodeURIComponent(err)}${errDesc ? `&error_description=${encodeURIComponent(errDesc.slice(0, 300))}` : ''}&state=${state}`
      : `code=${code ? maskCode(code) : ''}&state=${state}`;
    const callbackUrl = `${cfg.webAppRedirectUri}?${query}`;
    trace.add(runId, {
      stepId: 'wa-code', from: 'entra', to: 'browser', label: err ? '302 ?error&state' : '302 ?code&state', determinism: 'protocol',
      status: entraError ? 'error' : 'ok',
      response: { status: 302, statusText: 'Found', headers: { location: callbackUrl } },
      note: entraError ?? 'Entra sends the browser back with a one-time authorization code.',
    });

    const bindCookie = readCookie(req, 'wa_bind');
    trace.add(runId, {
      stepId: 'wa-callback', from: 'browser', to: 'webapp', label: 'GET /webapp/callback', determinism: 'protocol', status: 'ok',
      request: { method: 'GET', url: callbackUrl, headers: bindCookie ? { cookie: 'wa_bind=…[masked]' } : {} },
    });

    const ageMs = ctx.now() - entry.createdAt;
    const bindOk = safeEqual(bindCookie, entry.bindingId);
    const freshOk = ageMs <= PENDING_TTL_MS;
    const stateChecks = [
      { name: 'State found and unused', ok: true, detail: `state ${maskState(state)} matched a pending sign-in and was removed` },
      { name: 'wa_bind cookie matches', ok: bindOk, detail: bindCookie ? (bindOk ? 'Same browser that started the sign-in' : 'Cookie belongs to a different sign-in') : 'No wa_bind cookie' },
      { name: 'Not expired', ok: freshOk, detail: `${Math.round(ageMs / 1000)}s old, limit ${PENDING_TTL_MS / 1000}s` },
    ];
    const stateOk = bindOk && freshOk;
    trace.add(runId, {
      stepId: 'wa-state', from: 'webapp', to: 'webapp', label: 'Check state and binding cookie', determinism: 'protocol',
      status: stateOk ? 'ok' : 'error', checks: stateChecks,
      note: stateOk ? 'All checks passed' : `${stateChecks.find((c) => !c.ok).name} check failed`,
    });
    if (!stateOk) {
      trace.finish(runId, `${stateChecks.find((c) => !c.ok).name} check failed`);
      return sendError(res, 400, 'This sign-in response does not belong to this browser or has expired.');
    }
    res.append('Set-Cookie', `wa_bind=; ${COOKIE_ATTRS}; Max-Age=0`);
    if (entraError) {
      trace.finish(runId, entraError);
      return sendError(res, 400, entraError);
    }

    try {
      const form = {
        client_id: cfg.webAppClientId,
        grant_type: 'authorization_code',
        code,
        redirect_uri: cfg.webAppRedirectUri,
        code_verifier: entry.verifier,
        scope: GRAPH_SCOPES,
      };
      let noteReq;
      if (variant === 'certificate') {
        let built;
        try {
          built = await loadClientAssertion({
            clientId: cfg.webAppClientId, certPath: cfg.webAppCertPath, keyPath: cfg.webAppKeyPath, audience: cfg.tokenEndpoint, now: ctx.now(),
          });
        } catch (e) {
          trace.add(runId, {
            stepId: 'wa-cred', from: 'webapp', to: 'webapp', label: 'Load credential', determinism: 'protocol',
            status: 'error', note: `Could not build client assertion: ${e?.code ?? e?.message ?? 'error'}`,
          });
          throw new Error('Could not build client assertion from WEBAPP_CERT_PATH / WEBAPP_KEY_PATH');
        }
        form.client_assertion_type = JWT_BEARER;
        form.client_assertion = built.assertion;
        noteReq = `The app proves its identity with an RS256 client assertion signed by its certificate key, x5t ${built.x5t}. The key never leaves the server.`;
      } else {
        form.client_secret = cfg.webAppClientSecret;
        noteReq = 'The app proves its identity with its client secret. The browser never sees it.';
      }

      const tok = await entra.tokenRequest(runId, {
        stepPrefix: 'wa-token', from: 'webapp', to: 'entra',
        labelReq: 'Redeem code (authorization_code)', labelRes: 'Tokens for the web app', form, noteReq,
        checksRes: tokenChecks(variant),
      });

      const v = await validator.validateIdToken(tok.id_token, { audience: cfg.webAppClientId, nonce: entry.nonce });
      trace.add(runId, {
        stepId: 'wa-idtoken', from: 'webapp', to: 'webapp', label: 'Validate ID token', determinism: 'protocol',
        status: v.ok ? 'ok' : 'error', checks: v.checks,
        tokens: v.token ? [tokenEntry('id_token', v.token)].filter(Boolean) : undefined,
        note: v.ok ? 'All checks passed' : v.error,
      });
      if (!v.ok) {
        trace.finish(runId, v.error);
        return sendError(res, 400, `The ID token was rejected: ${v.error}.`);
      }

      sweep(sessions, SESSION_TTL_MS);
      const sessionId = b64url(32);
      const session = {
        tokens: {
          access_token: tok.access_token ?? null,
          refresh_token: tok.refresh_token ?? null,
          id_token: tok.id_token,
          expiresAt: typeof tok.expires_in === 'number' ? ctx.now() + tok.expires_in * 1000 : null,
        },
        name: v.payload.name ?? v.payload.preferred_username ?? null,
        createdAt: ctx.now(),
      };
      putCapped(sessions, sessionId, session);
      trace.add(runId, {
        stepId: 'wa-session', from: 'webapp', to: 'browser', label: 'Set session cookie', determinism: 'protocol', status: 'ok',
        response: { status: 200, statusText: 'OK', headers: { 'set-cookie': `wa_session=…[masked]; ${COOKIE_ATTRS}` } },
        note: 'The browser gets a session cookie. The tokens stay in the server\'s token cache.',
      });

      let me;
      try {
        me = await entra.graphGet(runId, 'wa-graph', 'webapp', 'graph', ME_PATH, tok.access_token, {
          labelReq: 'GET /me', labelRes: 'User profile',
        });
      } catch (e) {
        sessions.delete(sessionId);
        throw e;
      }
      const displayName = typeof me.displayName === 'string' && me.displayName !== '' ? me.displayName : (session.name ?? 'unknown user');
      session.name = displayName;

      trace.add(runId, {
        stepId: 'wa-page', from: 'webapp', to: 'browser', label: '200 page', determinism: 'protocol', status: 'ok',
        response: { status: 200, statusText: 'OK', headers: { 'content-type': 'text/html' }, body: `Hello ${displayName}` },
      });

      res.append('Set-Cookie', `wa_session=${sessionId}; ${COOKIE_ATTRS}; Max-Age=${SESSION_TTL_MS / 1000}`);
      const scriptNonce = crypto.randomBytes(16).toString('base64');
      const script = `(function () {
  if (window.opener) {
    window.opener.postMessage({ type: 'authflow-webapp-done', runId: ${JSON.stringify(runId)} }, location.origin);
    setTimeout(window.close, 2500);
  }
})();`;
      sendHtml(res, 200, page(
        'AuthFlow demo web app',
        `<p>Signed in to the demo web app as ${escapeHtml(displayName)}. The tokens stayed on the server.</p>`,
        scriptNonce, script,
      ), scriptNonce);
      trace.finish(runId);
      return undefined;
    } catch (e) {
      trace.finish(runId, errorMessage(e));
      return sendError(res, 502, errorMessage(e));
    }
  });

  return { pending, sessions };
}
