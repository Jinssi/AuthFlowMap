// JWT decoding (no verification) and masking helpers. Nothing that leaves this module
// may contain a full token, a signature segment or a secret.

export const SECRET_MASK = '••••••••[redacted]';

const JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
const SECRET_FIELDS = new Set(['client_secret', 'password']);
const FORM_TOKEN_FIELDS = new Set([
  'client_assertion', 'assertion', 'refresh_token', 'code', 'code_verifier', 'device_code',
]);
const JSON_TOKEN_FIELDS = new Set(['access_token', 'id_token', 'refresh_token']);
const JSON_OPAQUE_FIELDS = new Set(['device_code', 'code', 'client_secret']);

function b64urlJson(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Decode a compact JWS without verifying it. Returns {header, payload} or null. */
export function decodeJwt(raw) {
  if (typeof raw !== 'string' || raw.length > 64 * 1024 || !JWT_SHAPE.test(raw)) return null;
  const [h, p] = raw.split('.');
  try {
    const header = b64urlJson(h);
    const payload = b64urlJson(p);
    if (!isPlainObject(header) || !isPlainObject(payload)) return null;
    return { header, payload };
  } catch {
    return null;
  }
}

export function isJwt(raw) {
  return decodeJwt(raw) !== null;
}

/** Mask any token-like value for display. */
export function maskToken(raw) {
  if (raw === null || raw === undefined) return raw;
  const s = String(raw);
  if (isJwt(s)) {
    const [h, p] = s.split('.');
    return `${h.slice(0, 16)}….${p.slice(0, 12)}….[signature redacted]`;
  }
  return `${s.slice(0, 6)}…[redacted]`;
}

function maskOpaque(raw) {
  const s = String(raw);
  return isJwt(s) ? maskToken(s) : `${s.slice(0, 6)}…`;
}

/** Token entry for event.tokens[]: masked raw + decoded header/payload (never the signature). */
export function tokenEntry(label, raw) {
  const decoded = decodeJwt(raw);
  if (!decoded) return null;
  return { label, masked: maskToken(raw), header: decoded.header, payload: decoded.payload };
}

/** Mask an x-www-form-urlencoded body given as an object. */
export function maskForm(obj) {
  const body = {};
  const tokens = [];
  for (const [k, v] of Object.entries(obj ?? {})) {
    if (v === undefined || v === null) continue;
    if (SECRET_FIELDS.has(k)) {
      body[k] = SECRET_MASK;
    } else if (FORM_TOKEN_FIELDS.has(k)) {
      body[k] = maskOpaque(v);
      const t = tokenEntry(k, String(v));
      if (t) tokens.push(t);
    } else {
      body[k] = String(v);
    }
  }
  return { body, tokens };
}

/** Mask a JSON response body (token endpoint style). */
export function maskJsonBody(obj) {
  const tokens = [];
  if (!isPlainObject(obj)) return { body: obj, tokens };
  const body = {};
  for (const [k, v] of Object.entries(obj)) {
    if (JSON_TOKEN_FIELDS.has(k) && typeof v === 'string') {
      body[k] = maskToken(v);
      const t = tokenEntry(k, v);
      if (t) tokens.push(t);
    } else if (JSON_OPAQUE_FIELDS.has(k) && typeof v === 'string') {
      body[k] = k === 'client_secret' ? SECRET_MASK : maskOpaque(v);
    } else {
      body[k] = v;
    }
  }
  return { body, tokens };
}

/** Mask request headers. Authorization: Bearer <jwt> -> 'Bearer ' + maskToken. */
export function maskHeaders(headers) {
  const out = {};
  const tokens = [];
  for (const [k, v] of Object.entries(headers ?? {})) {
    const lk = k.toLowerCase();
    if (lk === 'authorization') {
      const m = /^Bearer\s+(.+)$/i.exec(String(v));
      if (m) {
        out[k] = `Bearer ${maskToken(m[1])}`;
        const t = tokenEntry('access_token', m[1]);
        if (t) tokens.push(t);
      } else {
        out[k] = '[redacted]';
      }
    } else if (lk === 'cookie' || lk === 'x-api-key') {
      out[k] = '[redacted]';
    } else {
      out[k] = String(v);
    }
  }
  return { headers: out, tokens };
}

export function truncateText(s, max = 4096) {
  const str = String(s ?? '');
  return str.length > max ? `${str.slice(0, max)}…[truncated ${str.length - max} chars]` : str;
}

/** Mask a user principal name for projection: first 3 chars + '…@domain'. Non-strings pass through. */
export function maskUpn(upn) {
  if (typeof upn !== 'string' || upn === '') return upn;
  const at = upn.lastIndexOf('@');
  if (at < 0) return `${upn.slice(0, 3)}…`;
  return `${upn.slice(0, Math.min(3, at))}…${upn.slice(at)}`;
}

/** Deep copy with every userPrincipalName property value masked with maskUpn. */
export function maskUpnsDeep(value, depth = 0) {
  if (depth > 20) return '[depth limit]';
  if (Array.isArray(value)) return value.map((v) => maskUpnsDeep(v, depth + 1));
  if (isPlainObject(value)) {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = k.toLowerCase() === 'userprincipalname' ? maskUpn(v) : maskUpnsDeep(v, depth + 1);
    }
    return out;
  }
  return value;
}

// ---- Value-based safety net ----
// The field-name masking above covers the places tokens are expected. These patterns catch
// token-shaped values anywhere else: error bodies, query strings, notes and unknown fields.

// Anything that looks like a compact JWS with a non-empty signature, anywhere in a string.
const EMBEDDED_JWT = /[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
// JWS / JWE shape: base64url segments separated by dots, the first one starting with eyJ ({").
const JWT_LIKE = /eyJ[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]*){2,4}/g;
// Entra ID client secret format: 3 chars, a digit, "Q~", then 31 to 34 chars.
const ENTRA_SECRET = /[A-Za-z0-9_~.-]{3}\dQ~[A-Za-z0-9_~.-]{31,34}/g;
// Authorization header value (also URL-encoded: Bearer%20... or Bearer+...).
const BEARER = /\b(Bearer)(\s+|%20|\+)([A-Za-z0-9\-._~+/]+=*)/gi;
const SENSITIVE_NAMES = 'access_token|refresh_token|id_token|client_secret|client_assertion|assertion|device_code|code_verifier|code|password';
const SECRET_NAMES = new Set(['client_secret', 'password']);
// name=value in a query string or form body.
const QUERY_PARAM = new RegExp(`(^|[?&#;\\s])(${SENSITIVE_NAMES})=([^&#\\s"'<>]+)`, 'gi');
// "name": "value" in JSON text (for example a truncated response body).
const JSON_PARAM = new RegExp(`("(?:${SENSITIVE_NAMES})"\\s*:\\s*")([^"]+)(")`, 'gi');
// Long opaque base64url blob (refresh token, authorization code, device code), dots allowed.
const OPAQUE_RUN = /[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*/g;
const OPAQUE_MIN = 64;

const isMasked = (v) => v.includes('…') || v === SECRET_MASK || v.startsWith('[redacted');

function maskNamedValue(name, value) {
  if (isMasked(value)) return value;
  return SECRET_NAMES.has(name.toLowerCase()) ? SECRET_MASK : maskToken(value);
}

// A single base64 segment that decodes to a JSON object (for example a claims challenge) is not a token.
function isBase64Json(run) {
  if (run.includes('.') || !run.startsWith('eyJ')) return false;
  try {
    const v = JSON.parse(Buffer.from(run, 'base64url').toString('utf8'));
    return v !== null && typeof v === 'object';
  } catch {
    return false;
  }
}

function looksOpaque(run) {
  return run.length >= OPAQUE_MIN && /\d/.test(run) && /[A-Z]/.test(run) && /[a-z]/.test(run) && !isBase64Json(run);
}

function scrubString(s, secrets) {
  let out = s;
  for (const secret of secrets) {
    if (secret && out.includes(secret)) out = out.split(secret).join(SECRET_MASK);
  }
  out = out.replace(ENTRA_SECRET, SECRET_MASK);
  out = out.replace(JWT_LIKE, (m) => maskToken(m));
  out = out.replace(EMBEDDED_JWT, (m) => (isJwt(m) ? maskToken(m) : m));
  out = out.replace(BEARER, (m, word, sep, val, offset, str) => {
    const next = str[offset + m.length] ?? '';
    // Skip short words ("Bearer token"), auth-params (Bearer error="...") and values already masked.
    if (val.length < 20 || next === '…' || /^[A-Za-z_]+=$/.test(val)) return m;
    return `${word}${sep}${maskToken(val)}`;
  });
  out = out.replace(JSON_PARAM, (m, pre, val, post) => `${pre}${maskNamedValue(pre.slice(1, pre.indexOf('"', 1)), val)}${post}`);
  out = out.replace(QUERY_PARAM, (m, pre, name, val) => `${pre}${name}=${maskNamedValue(name, val)}`);
  out = out.replace(OPAQUE_RUN, (m) => (looksOpaque(m) ? maskToken(m) : m));
  return out;
}

/** Mask token-shaped values and known secrets in one string (also for text reflected in HTML). */
export function scrubText(s, secrets = []) {
  return scrubString(String(s ?? ''), secrets);
}

/**
 * Safety net applied to every trace event: masks token-shaped values (JWTs, Bearer values,
 * client secrets, long opaque blobs, sensitive query/JSON parameters) in every string and every
 * object key, and replaces known secret values. Returns a deep copy.
 */
export function scrubDeep(value, secrets = [], depth = 0) {
  if (depth > 20) return '[depth limit]';
  if (typeof value === 'string') return scrubString(value, secrets);
  if (Array.isArray(value)) return value.map((v) => scrubDeep(v, secrets, depth + 1));
  if (isPlainObject(value)) {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[scrubString(k, secrets)] = scrubDeep(v, secrets, depth + 1);
    return out;
  }
  return value;
}
