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

      let sigOk = false;
      let sigDetail;
      const ks = getKeySet();
      if (!decoded) {
        sigDetail = 'Not a JWT';
      } else if (!ks) {
        sigDetail = 'Tenant not configured (TENANT_ID missing)';
      } else {
        try {
          // Signature is verified first; claim checks are evaluated separately below for display.
          await jwtVerify(token, ks, { algorithms: ['RS256'], clockTolerance: CLOCK_TOLERANCE, currentDate: new Date(now()) });
          sigOk = true;
          sigDetail = `alg ${decoded.header.alg}, kid ${kid} found in tenant JWKS`;
        } catch (e) {
          if (e?.code === 'ERR_JWT_EXPIRED' || e?.code === 'ERR_JWT_CLAIM_VALIDATION_FAILED') {
            sigOk = true; // jose only checks claims after a valid signature
            sigDetail = `alg ${decoded.header.alg}, kid ${kid} found in tenant JWKS`;
          } else {
            sigDetail = `${e?.code ?? 'error'}: ${e?.message ?? e}`;
          }
        }
      }

      const nowSec = Math.floor(now() / 1000);
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      const audOk = audiences.length > 0 && aud.some((a) => audiences.includes(a));
      const issOk = issuers.includes(payload.iss) && !!cfg.tenantId;
      const expOk = typeof payload.exp === 'number' && nowSec <= payload.exp + CLOCK_TOLERANCE
        && (typeof payload.nbf !== 'number' || payload.nbf <= nowSec + CLOCK_TOLERANCE);
      const tidOk = !!cfg.tenantId && payload.tid === cfg.tenantId;
      const scopes = typeof payload.scp === 'string' ? payload.scp.split(' ') : [];
      const scpOk = !!requiredScope && scopes.includes(requiredScope);
      const unverified = sigOk ? '' : ' (claims unverified: signature failed)';

      const checks = [
        { name: `Signature (JWKS kid ${kid})`, ok: sigOk, detail: sigDetail },
        { name: 'Issuer', ok: issOk, detail: `iss ${payload.iss ?? '(none)'}${unverified}` },
        { name: 'Audience', ok: audOk, detail: `aud ${aud.join(', ') || '(none)'}; expected one of ${audiences.join(', ') || '(not configured)'}${unverified}` },
        {
          name: 'Expiry', ok: expOk,
          detail: typeof payload.exp === 'number'
            ? `exp ${new Date(payload.exp * 1000).toISOString()} (${payload.exp - nowSec}s left, ${CLOCK_TOLERANCE}s tolerance)${unverified}`
            : 'no exp claim',
        },
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

  return { validateBearer };
}
