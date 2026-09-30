// Small shared helpers for browser-initiated handlers.
import { UpstreamError } from './entra.js';
import { isValidRunId } from './trace.js';

/** Returns runId (string), null when no X-Run-Id header, or false after sending 400. */
export function readRunIdHeader(req, res) {
  const h = req.get('x-run-id');
  if (h === undefined || h === '') return null;
  if (!isValidRunId(h)) {
    res.status(400).json({ error: 'invalid_run_id', error_description: 'X-Run-Id must match ^[A-Za-z0-9_-]{8,64}$' });
    return false;
  }
  return h;
}

export function errorMessage(e) {
  if (e instanceof UpstreamError) return `${e.error}: ${e.error_description}`;
  return String(e?.message ?? e ?? 'Unknown error');
}

export function upstreamBody(e) {
  if (e instanceof UpstreamError) return { error: e.error, error_description: e.error_description };
  return { error: 'server_error', error_description: errorMessage(e) };
}

/** RFC 6750 quoted-string safe value. */
export function q(s) {
  return String(s ?? '').replace(/["\\\r\n]/g, ' ');
}
