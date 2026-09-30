// Raw Entra ID / Microsoft Graph HTTP calls. Every request and response is recorded as a
// masked trace event so it can be shown to an audience.
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { maskForm, maskHeaders, maskJsonBody, truncateText, tokenEntry } from './mask.js';

export const GRAPH_BASE = 'https://graph.microsoft.com/v1.0';
const RESPONSE_HEADERS = ['content-type', 'www-authenticate', 'mcp-session-id'];

/** Upstream (Entra / Graph / network) failure. Message never contains tokens or secrets. */
export class UpstreamError extends Error {
  constructor(status, error, errorDescription) {
    super(`${error}: ${errorDescription}`);
    this.name = 'UpstreamError';
    this.status = status;
    this.error = error;
    this.error_description = errorDescription;
  }
}

function pickHeaders(h) {
  const out = {};
  for (const k of RESPONSE_HEADERS) {
    const v = h?.get?.(k);
    if (v) out[k] = v;
  }
  return out;
}

/** Normalize an Entra ({error, error_description}) or Graph ({error:{code,message}}) failure. */
export function errorInfo(r) {
  if (r.networkError) return { error: 'upstream_unreachable', error_description: r.networkError };
  const j = r.json;
  if (j && typeof j.error === 'string') {
    const desc = typeof j.error_description === 'string' ? j.error_description.split(/\r?\n/)[0] : '';
    return { error: j.error, error_description: desc || `HTTP ${r.status}` };
  }
  if (j && j.error && typeof j.error === 'object') {
    return { error: String(j.error.code ?? `http_${r.status}`), error_description: String(j.error.message ?? '') };
  }
  return { error: `http_${r.status}`, error_description: r.statusText || 'Unexpected response' };
}

export function createEntra({ cfg, trace, fetchImpl = globalThis.fetch, timeoutMs = 20000 }) {
  async function http(method, url, { headers = {}, body } = {}) {
    try {
      const res = await fetchImpl(url, {
        method, headers, body, redirect: 'error', signal: AbortSignal.timeout(timeoutMs),
      });
      const text = await res.text();
      let json = null;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        json = null;
      }
      return { ok: res.ok, status: res.status, statusText: res.statusText, headers: pickHeaders(res.headers), text, json };
    } catch (e) {
      const msg = e?.name === 'TimeoutError' ? `Request timed out after ${timeoutMs} ms` : String(e?.cause?.code ?? e?.message ?? e);
      return { ok: false, status: 0, statusText: 'Network error', headers: {}, text: '', json: null, networkError: msg };
    }
  }

  function postForm(url, form) {
    const body = new URLSearchParams();
    for (const [k, v] of Object.entries(form)) if (v !== undefined && v !== null) body.set(k, String(v));
    return http('POST', url, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: body.toString(),
    });
  }

  function recordFormRequest(runId, { stepId, from, to, label, url, form, determinism = 'protocol', note, data }) {
    const { body, tokens } = maskForm(form);
    return trace.add(runId, {
      stepId, from, to, label, determinism, status: 'ok',
      request: { method: 'POST', url, headers: { 'content-type': 'application/x-www-form-urlencoded' }, body },
      tokens, note, data,
    });
  }

  function responseView(r) {
    let body;
    let tokens = [];
    if (r.json !== null && typeof r.json === 'object') {
      ({ body, tokens } = maskJsonBody(r.json));
      if (JSON.stringify(body).length > 16384) body = truncateText(JSON.stringify(body), 4096);
    } else {
      body = truncateText(r.text, 4096);
    }
    return { response: { status: r.status, statusText: r.statusText, headers: r.headers, body }, tokens };
  }

  function recordResponse(runId, { stepId, from, to, label, r, determinism = 'protocol', status, note, data, checks }) {
    const { response, tokens } = responseView(r);
    const st = status ?? (r.ok ? 'ok' : 'error');
    let n = note;
    if (!n && st === 'error') {
      const e = errorInfo(r);
      n = `${e.error}: ${e.error_description}`;
    }
    return trace.add(runId, { stepId, from, to, label, determinism, status: st, response, tokens, note: n, data, checks });
  }

  /**
   * opts.checksRes(json, ok, errorInfo) optionally returns a checks list for the `-res` event
   * (called on success and on failure).
   */
  async function formExchange(url, runId, { stepPrefix, from, to, labelReq, labelRes, form, noteReq, noteRes, dataRes, checksRes }) {
    recordFormRequest(runId, { stepId: `${stepPrefix}-req`, from, to, label: labelReq, url, form, note: noteReq });
    const r = await postForm(url, form);
    if (!r.ok || !r.json || typeof r.json !== 'object') {
      const e = r.ok ? { error: 'invalid_response', error_description: 'Expected a JSON response' } : errorInfo(r);
      recordResponse(runId, {
        stepId: `${stepPrefix}-res`, from: to, to: from, label: labelRes, r, status: 'error',
        note: `${e.error}: ${e.error_description}`,
        checks: typeof checksRes === 'function' ? checksRes(r.json, false, e) : undefined,
      });
      throw new UpstreamError(r.status || 502, e.error, e.error_description);
    }
    recordResponse(runId, {
      stepId: `${stepPrefix}-res`, from: to, to: from, label: labelRes, r,
      note: typeof noteRes === 'function' ? noteRes(r.json) : noteRes,
      data: typeof dataRes === 'function' ? dataRes(r.json) : dataRes,
      checks: typeof checksRes === 'function' ? checksRes(r.json, true, null) : undefined,
    });
    return r.json;
  }

  /** POST /oauth2/v2.0/token, recording `${stepPrefix}-req` / `${stepPrefix}-res`. */
  function tokenRequest(runId, opts) {
    return formExchange(cfg.tokenEndpoint, runId, {
      noteRes: (j) => [j.token_type && `token_type ${j.token_type}`, j.expires_in && `expires_in ${j.expires_in}s`, j.scope && `scope ${j.scope}`]
        .filter(Boolean).join(', ') || undefined,
      ...opts,
    });
  }

  /** POST /oauth2/v2.0/devicecode, recording `${stepPrefix}-req` / `${stepPrefix}-res`. */
  function deviceCodeRequest(runId, opts) {
    return formExchange(cfg.deviceCodeEndpoint, runId, opts);
  }

  /** Record a Graph response as `${stepPrefix}-res`; throws UpstreamError on failure. */
  function finishGraph(runId, { stepPrefix, from, to, r, labelRes, maskBody, dataRes }) {
    const labelResponse = labelRes ?? 'Graph response';
    const view = maskBody && r.json ? { ...r, json: maskBody(r.json) } : r;
    if (!r.ok || !r.json) {
      const e = r.ok ? { error: 'invalid_response', error_description: 'Expected a JSON response' } : errorInfo(r);
      recordResponse(runId, { stepId: `${stepPrefix}-res`, from: to, to: from, label: labelResponse, r: view, status: 'error', note: `${e.error}: ${e.error_description}` });
      throw new UpstreamError(r.status || 502, e.error, e.error_description);
    }
    recordResponse(runId, {
      stepId: `${stepPrefix}-res`, from: to, to: from, label: labelResponse, r: view,
      data: typeof dataRes === 'function' ? dataRes(r.json) : dataRes,
    });
    return r.json;
  }

  /**
   * GET https://graph.microsoft.com/v1.0{path}, recording `${stepPrefix}-req` / `${stepPrefix}-res`.
   * opts.maskBody transforms the recorded response body only (the caller gets the raw JSON).
   */
  async function graphGet(runId, stepPrefix, from, to, path, token, { labelReq, labelRes, maskBody, dataRes } = {}) {
    const url = `${GRAPH_BASE}${path}`;
    const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
    const masked = maskHeaders(headers);
    trace.add(runId, {
      stepId: `${stepPrefix}-req`, from, to, label: labelReq ?? `GET ${path.split('?')[0]}`, determinism: 'protocol', status: 'ok',
      request: { method: 'GET', url, headers: masked.headers }, tokens: masked.tokens,
    });
    const r = await http('GET', url, { headers });
    return finishGraph(runId, { stepPrefix, from, to, r, labelRes, maskBody, dataRes });
  }

  /** POST a JSON body to https://graph.microsoft.com/v1.0{path}, recording `${stepPrefix}-req` / `${stepPrefix}-res`. */
  async function graphPost(runId, stepPrefix, from, to, path, token, payload, { labelReq, labelRes, noteReq, maskBody, dataRes } = {}) {
    const url = `${GRAPH_BASE}${path}`;
    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'application/json' };
    const masked = maskHeaders(headers);
    trace.add(runId, {
      stepId: `${stepPrefix}-req`, from, to, label: labelReq ?? `POST ${path.split('?')[0]}`, determinism: 'protocol', status: 'ok',
      request: { method: 'POST', url, headers: masked.headers, body: payload }, tokens: masked.tokens, note: noteReq,
    });
    const r = await http('POST', url, { headers, body: JSON.stringify(payload) });
    return finishGraph(runId, { stepPrefix, from, to, r, labelRes, maskBody, dataRes });
  }

  return {
    http, postForm, recordFormRequest, recordResponse, tokenRequest, deviceCodeRequest, graphGet, graphPost,
  };
}

/**
 * Build an RS256 client assertion (RFC 7523) for certificate credentials.
 * x5t = base64url(SHA-1 of the DER certificate).
 */
export function buildClientAssertion({ clientId, certPem, keyPem, audience, now = Date.now() }) {
  const cert = new crypto.X509Certificate(certPem);
  const x5t = crypto.createHash('sha1').update(cert.raw).digest('base64url');
  const key = crypto.createPrivateKey(keyPem); // handles PKCS#8 and PKCS#1 PEM
  const iat = Math.floor(now / 1000);
  const header = { alg: 'RS256', typ: 'JWT', x5t };
  const payload = { aud: audience, iss: clientId, sub: clientId, jti: crypto.randomUUID(), nbf: iat, iat, exp: iat + 300 };
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const signingInput = `${enc(header)}.${enc(payload)}`;
  const signature = crypto.sign('sha256', Buffer.from(signingInput), key).toString('base64url');
  return { assertion: `${signingInput}.${signature}`, x5t, subject: cert.subject, validTo: cert.validTo };
}

/**
 * Read a PEM certificate and private key from disk and build a client assertion with them.
 * Shared by the daemon (client credentials) and the confidential web app. Throws on read/parse errors.
 */
export async function loadClientAssertion({ clientId, certPath, keyPath, audience, now = Date.now() }) {
  const [certPem, keyPem] = await Promise.all([
    fs.readFile(certPath, 'utf8'), fs.readFile(keyPath, 'utf8'),
  ]);
  return buildClientAssertion({ clientId, certPem, keyPem, audience, now });
}

export { tokenEntry };
