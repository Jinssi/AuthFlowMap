'use strict';
/* =====================================================================
   CONFIG. Change the tenant, app, API and agent names and IDs here to rebrand the demo.
   Simulated mode builds every request and token from these values.
   ===================================================================== */
const ID = {
  tenantName: 'Contoso',
  tenantDomain: 'contoso.onmicrosoft.com',
  tid: 'b5c1e7a2-4f0d-4a53-9c8e-2d7f1a6e9b40',
  user: { name: 'Alex Johnson', upn: 'alex@contoso.com', oid: '3f2a9c71-5e8b-4d0a-a1c6-7b9e2f4d8c10' },
  spa: { name: 'Contoso Portal (SPA)', appId: '6e1c2b7a-3d4f-4a5b-9c8d-1e2f3a4b5c6d' },
  api: { name: 'Orders API', appId: '9a8b7c6d-5e4f-4321-8a9b-0c1d2e3f4a5b', spOid: 'c4d3e2f1-0a9b-4c8d-9e7f-6a5b4c3d2e1f' },
  daemon: { name: 'Nightly Sync Job', appId: '2b3c4d5e-6f7a-4b8c-9d0e-1f2a3b4c5d6e', spOid: 'd1e2f3a4-b5c6-4d7e-8f9a-0b1c2d3e4f5a' },
  mcp: { name: 'Contoso MCP Server', appId: '7c8d9e0f-1a2b-4c3d-8e4f-5a6b7c8d9e0f', spOid: 'e5f6a7b8-c9d0-4e1f-a2b3-c4d5e6f7a8b9', url: 'https://mcp.contoso.com/mcp' },
  blueprint: { name: 'Contoso Assistant Blueprint', appId: '4d5e6f7a-8b9c-4d0e-a1f2-3b4c5d6e7f8a', spOid: 'f1a2b3c4-d5e6-4f7a-8b9c-0d1e2f3a4b5c' },
  agent: { name: 'Contoso Assistant #1', appId: '8e9f0a1b-2c3d-4e5f-9a0b-1c2d3e4f5a6b', spOid: 'a9b8c7d6-e5f4-4a3b-2c1d-0e9f8a7b6c5d' },
  agentUser: { name: 'Contoso Assistant (mailbox)', upn: 'assistant1@contoso.com', oid: '5b6c7d8e-9f0a-4b1c-2d3e-4f5a6b7c8d9e' },
  orchestrator: { name: 'Orchestrator agent', appId: '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d' },
  subagent: { name: 'Finance agent', appId: '3c4d5e6f-7a8b-4c9d-0e1f-2a3b4c5d6e7f' },
  mi: { name: 'Contoso Web App (managed identity)', clientId: '0f1e2d3c-4b5a-4968-8778-695a4b3c2d1e', oid: '6d5c4b3a-2918-4f7e-a6d5-c4b3a2918f7e' },
  wif: { name: 'GitHub Actions deploy', appId: '5e4d3c2b-1a09-4f8e-b7d6-c5b4a3928170', repo: 'contoso/orders-api' },
  downstream: { name: 'ERP API', uri: 'api://contoso-erp', appId: 'aa11bb22-cc33-4d44-8e55-ff6677889900' },
  graphAppId: '00000003-0000-0000-c000-000000000000',
  port: 5100,
};
const AUTHORITY = `https://login.microsoftonline.com/${ID.tid}`;
const TOKEN_EP = `${AUTHORITY}/oauth2/v2.0/token`;
const AUTHZ_EP = `${AUTHORITY}/oauth2/v2.0/authorize`;
const ISS_V2 = `${AUTHORITY}/v2.0`;
const GRAPH = 'https://graph.microsoft.com';

/* ---------- small utilities shared by all scripts ---------- */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const nowSec = () => Math.floor(Date.now() / 1000);

function b64url(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(seg) {
  const s = seg.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 ? '='.repeat(4 - (s.length % 4)) : '';
  const bin = atob(s + pad);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
function randStr(n, alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_') {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return Array.from(a, (x) => alphabet[x % alphabet.length]).join('');
}
function uuid() { return crypto.randomUUID ? crypto.randomUUID() : `${randStr(8)}-${randStr(4)}-${randStr(4)}-${randStr(4)}-${randStr(12)}`; }

/** A JWT that decodes like a real one but carries a random, meaningless signature. Simulated mode only. */
function fakeJwt(header, payload) {
  return `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}.${randStr(86)}`;
}
function decodeJwt(raw) {
  try {
    const [h, p] = String(raw).split('.');
    if (!h || !p) return null;
    return { header: JSON.parse(b64urlDecode(h)), payload: JSON.parse(b64urlDecode(p)) };
  } catch { return null; }
}
/** Same masking rule as the server. Keep a short prefix of the header and payload and drop the signature. */
function maskToken(raw) {
  const s = String(raw || '');
  const parts = s.split('.');
  if (parts.length === 3 && parts[0].startsWith('eyJ')) return `${parts[0].slice(0, 16)}….${parts[1].slice(0, 12)}….[signature redacted]`;
  return s ? `${s.slice(0, 6)}…[redacted]` : '';
}
const isJwt = (s) => typeof s === 'string' && /^eyJ[\w-]*\.[\w-]+\.[\w-]*$/.test(s);
