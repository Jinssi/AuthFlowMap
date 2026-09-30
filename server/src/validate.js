// Bearer token validation against the tenant JWKS (jose). Never throws.
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { decodeJwt } from './mask.js';

const CLOCK_TOLERANCE = 60;

export function extractBearer(req) {
  const h = req.headers?.authorization;
  if (typeof h !== 'string') return null;
  const m = /^Bearer\s+([A-Za-z0-9._~+/=-]+)\s*$/i.exec(h);
  return m ? m[1] : null;
}

/**
 * @param {object} opts
 * @param {object} opts.cfg
 * @param {Function} [opts.jwks] jose key resolver (tests inject createLocalJWKSet)
 */
export function createValidator({ cfg, jwks, now = () => Date.now() }) {
  let keySet = jwks ?? null;
  function getKeySet() {
    if (!keySet && cfg.tenantId) keySet = createRemoteJWKSet(new URL(cfg.jwksUri), { timeoutDuration: 10000 });
    return keySet;
  }

  /** Verify the RS256 signature against the tenant JWKS. Claim checks are evaluated separately for display. */
  async function verifySignature(token, decoded) {
    const kid = decoded?.header?.kid ?? 'unknown';
    const ks = getKeySet();
    if (!decoded) return { sigOk: false, sigDetail: 'Not a JWT' };
    if (!ks) return { sigOk: false, sigDetail: 'Tenant not configured (TENANT_ID missing)' };
    try {
      await jwtVerify(token, ks, { algorithms: ['RS256'], clockTolerance: CLOCK_TOLERANCE, currentDate: new Date(now()) });
      return { sigOk: true, sigDetail: `alg ${decoded.header.alg}, kid ${kid} found in tenant JWKS` };
    } catch (e) {
      if (e?.code === 'ERR_JWT_EXPIRED' || e?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
        // jose only checks claims after a valid signature
        return { sigOk: true, sigDetail: `alg ${decoded.header.alg}, kid ${kid} found in tenant JWKS` };
      }
      return { sigOk: false, sigDetail: `${e?.code ?? 'error'}: ${e?.message ?? e}` };
    }
  }

  function expiryCheck(payload, nowSec, unverified) {
    const expOk = typeof payload.exp === 'number' && nowSec <= payload.exp + CLOCK_TOLERANCE
      && (typeof payload.nbf !== 'number' || payload.nbf <= nowSec + CLOCK_TOLERANCE);
    return {
      name: 'Expiry', ok: expOk,
      detail: typeof payload.exp === 'number'
        ? `exp ${new Date(payload.exp * 1000).toISOString()} (${payload.exp - nowSec}s left, ${CLOCK_TOLERANCE}s tolerance)${unverified}`
        : 'no exp claim',
    };
  }

  async function validateBearer(req, { expectedAudiences = [], requiredScope } = {}) {
    const token = extractBearer(req);
    if (!token) {
      return {
        ok: false, missing: true, token: null, payload: null,
        checks: [{ name: 'Bearer token present', ok: false, detail: 'No Authorization: Bearer header' }],
        error: 'No bearer token',
      };
    }
    try {
      const decoded = decodeJwt(token);
      const kid = decoded?.header?.kid ?? 'unknown';
      const payload = decoded?.payload ?? {};
      const audiences = expectedAudiences.filter(Boolean);
      const issuers = [cfg.issuerV2, cfg.issuerV1];

      const { sigOk, sigDetail } = await verifySignature(token, decoded);

      const nowSec = Math.floor(now() / 1000);
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      const audOk = audiences.length > 0 && aud.some((a) => audiences.includes(a));
      const issOk = issuers.includes(payload.iss) && !!cfg.tenantId;
      const tidOk = !!cfg.tenantId && payload.tid === cfg.tenantId;
      const scopes = typeof payload.scp === 'string' ? payload.scp.split(' ') : [];
      const scpOk = !!requiredScope && scopes.includes(requiredScope);
      const unverified = sigOk ? '' : ' (claims unverified: signature failed)';

      const checks = [
        { name: `Signature (JWKS kid ${kid})`, ok: sigOk, detail: sigDetail },
        { name: 'Issuer', ok: issOk, detail: `iss ${payload.iss ?? '(none)'}${unverified}` },
        { name: 'Audience', ok: audOk, detail: `aud ${aud.join(', ') || '(none)'}; expected one of ${audiences.join(', ') || '(not configured)'}${unverified}` },
        expiryCheck(payload, nowSec, unverified),
        { name: 'Tenant (tid)', ok: tidOk, detail: `tid ${payload.tid ?? '(none)'}${unverified}` },
        { name: `Scope scp contains ${requiredScope}`, ok: scpOk, detail: `scp ${payload.scp ?? '(none)'}${unverified}` },
      ];
      const ok = checks.every((c) => c.ok);
      const failed = checks.find((c) => !c.ok);
      return { ok, token, payload: decoded ? payload : null, checks, error: ok ? null : `${failed.name} check failed` };
    } catch (e) {
      return {
        ok: false, token, payload: null,
        checks: [{ name: 'Token validation', ok: false, detail: String(e?.message ?? e) }],
        error: 'Token validation failed',
      };
    }
  }

  /**
   * Validate an OpenID Connect ID token: signature, v2 issuer, audience = client id, expiry and nonce.
   * Never throws.
   */
  async function validateIdToken(token, { audience, nonce } = {}) {
    if (typeof token !== 'string' || token === '') {
      return {
        ok: false, token: null, payload: null,
        checks: [{ name: 'ID token present', ok: false, detail: 'No id_token in the token response' }],
        error: 'No ID token',
      };
    }
    try {
      const decoded = decodeJwt(token);
      const kid = decoded?.header?.kid ?? 'unknown';
      const payload = decoded?.payload ?? {};
      const { sigOk, sigDetail } = await verifySignature(token, decoded);
      const nowSec = Math.floor(now() / 1000);
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      const audOk = !!audience && aud.includes(audience);
      const issOk = !!cfg.tenantId && payload.iss === cfg.issuerV2;
      const nonceOk = typeof nonce === 'string' && nonce !== '' && payload.nonce === nonce;
      const unverified = sigOk ? '' : ' (claims unverified: signature failed)';

      const checks = [
        { name: `Signature (JWKS kid ${kid})`, ok: sigOk, detail: sigDetail },
        { name: 'Issuer', ok: issOk, detail: `iss ${payload.iss ?? '(none)'}; expected ${cfg.issuerV2}${unverified}` },
        { name: 'Audience', ok: audOk, detail: `aud ${aud.join(', ') || '(none)'}; expected ${audience ?? '(not configured)'}${unverified}` },
        expiryCheck(payload, nowSec, unverified),
        {
          name: 'Nonce', ok: nonceOk,
          detail: `nonce ${payload.nonce ?? '(none)'}; expected ${nonce ?? '(none)'}${unverified}`,
        },
      ];
      const ok = checks.every((c) => c.ok);
      const failed = checks.find((c) => !c.ok);
      return { ok, token, payload: decoded ? payload : null, checks, error: ok ? null : `${failed.name} check failed` };
    } catch (e) {
      return {
        ok: false, token, payload: null,
        checks: [{ name: 'ID token validation', ok: false, detail: String(e?.message ?? e) }],
        error: 'ID token validation failed',
      };
    }
  }

  return { validateBearer, validateIdToken };
}
