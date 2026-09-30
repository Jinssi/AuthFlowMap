'use strict';
/* =====================================================================
   FLOW DEFINITIONS: standard OAuth 2.0 / OIDC (part 1)
   Step fields: id, from, to, label, title, det (protocol|ai|human|policy),
   desc, why, req {method,url,query,headers,form,json}, res {status,statusText,headers,json,form,text},
   tok [token names], checks [{name,ok,detail}], kv {key:value}.
   '{{name}}' placeholders resolve to simulated tokens (ctx.raw) or run variables (ctx.vars).
   ===================================================================== */
const FLOWS = [];
const HDR = {
  form: { 'Content-Type': 'application/x-www-form-urlencoded' },
  json: { 'Content-Type': 'application/json' },
  bearer: (n) => ({ Authorization: `Bearer {{${n}}}` }),
};
const SCOPE = {
  api: `api://${ID.api.appId}/access_as_user`,
  mcp: `api://${ID.mcp.appId}/mcp.tools`,
  blueprint: `api://${ID.blueprint.appId}/access_as_user`,
  graphUser: 'openid profile offline_access User.Read',
};
const REDIRECT = 'https://portal.contoso.com/auth-callback';
const ORIGIN = 'https://portal.contoso.com';

/** Reusable browser sign-in (auth code + PKCE) segment. p = step id prefix, tokName = resulting access token. */
function pkceSignInSteps(p, { client = 'browser', scope, tokName, audName, short = false, clientId = ID.spa.appId, redirect = REDIRECT, extraQuery = {}, device = 'unknown' }) {
  const managedDev = device === 'managed';
  const steps = [
    { id: `${p}-pkce`, from: client, to: client, label: 'PKCE verifier + challenge', title: 'Generate PKCE, state and nonce', det: 'protocol',
      desc: 'The client makes a random <code>code_verifier</code> and keeps it to itself. Only the SHA-256 hash of it, the <code>code_challenge</code>, goes out. <code>state</code> guards the callback against cross-site request forgery, and <code>nonce</code> ties the ID token to this one sign-in.',
      why: 'Say an attacker grabs the authorization code off the redirect. It\'s useless to them, because redeeming it needs the verifier and the verifier never left this client.',
      kv: { code_verifier: '{{verifier}}', code_challenge: '{{challenge}}', method: 'S256', state: '{{state}}', nonce: '{{nonce}}' } },
    { id: `${p}-authz`, from: client, to: 'entra', label: 'GET /authorize', title: 'Redirect to the Entra authorize endpoint', det: 'protocol',
      desc: `The browser goes to Entra ID with the client ID, the redirect URI, the PKCE challenge and the scope <code>${esc(scope)}</code>. There\'s no secret anywhere in this request.`,
      req: { method: 'GET', url: AUTHZ_EP, query: { client_id: clientId, response_type: 'code', redirect_uri: redirect, response_mode: 'query', scope, state: '{{state}}', nonce: '{{nonce}}', code_challenge: '{{challenge}}', code_challenge_method: 'S256', ...extraQuery } } },
    managedDev ? { id: `${p}-signin`, from: 'entra', to: 'user', label: 'Silent SSO via PRT', title: 'No prompt at all', det: 'protocol',
      desc: 'The browser runs on a managed laptop, so it adds a PRT cookie signed inside the TPM. Entra already knows the user did Windows Hello this morning and which device this is.',
      why: 'Single sign-on and the device claim both come from the PRT. The Device identity tab shows how it gets issued.' } : { id: `${p}-signin`, from: 'entra', to: 'user', label: 'Sign-in + MFA', title: 'User authenticates at Entra ID', det: 'human',
      desc: 'The user enters credentials or a passkey and completes MFA <b>on the Entra ID page</b>. The app never sees the password.',
      why: 'The app never touches a credential. That\'s why you can roll out passkeys or phishing-resistant MFA without changing a line of app code.' },
    { id: `${p}-policy`, from: 'entra', to: 'entra', label: 'CA + consent', title: 'Conditional Access and consent evaluated', det: 'policy',
      desc: 'Entra runs Conditional Access, which looks at device compliance, location, sign-in risk and MFA strength. It also checks that someone has consented to the requested scopes. If nobody has, Entra asks the user, or an admin when the scope needs one.',
      checks: managedDev
        ? [{ name: 'Device identity presented through the PRT', ok: true }, { name: 'Device compliant in Intune', ok: true }, { name: 'MFA already in the PRT, no prompt needed', ok: true }, { name: 'Consent for requested scopes', ok: true, detail: 'Admin consent granted tenant-wide' }]
        : [{ name: 'Device identity presented', ok: false, detail: 'Unknown personal device' }, { name: 'MFA completed', ok: true }, { name: 'Unmanaged device policy: browser only, restricted session', ok: true }, { name: 'Consent for requested scopes', ok: true, detail: 'Admin consent granted tenant-wide' }] },
    { id: `${p}-code`, from: 'entra', to: client, label: '302 ?code&state', title: 'Authorization code returned', det: 'protocol',
      desc: 'Entra sends the browser back to the registered redirect URI with an authorization code. The code works once and expires after about 10 minutes.',
      res: { status: 302, statusText: 'Found', headers: { Location: `${redirect}?code={{code}}&state={{state}}&session_state={{sid}}` } } },
    { id: `${p}-state`, from: client, to: client, label: 'Verify state', title: 'Client verifies state', det: 'protocol',
      desc: 'The client compares the returned <code>state</code> with the value it stored. If they differ, someone forged the callback and the client stops here.',
      checks: [{ name: 'state matches stored value', ok: true, detail: '{{state}}' }] },
    { id: `${p}-token-req`, from: client, to: 'entra', label: 'POST /token (code + verifier)', title: 'Redeem code for tokens', det: 'protocol',
      desc: 'The client sends the code back with the <b>original verifier</b>. A SPA calls /token straight from the browser. Entra allows that cross-origin call only for redirect URIs registered under the SPA platform.',
      req: { method: 'POST', url: TOKEN_EP, headers: client === 'browser' ? { ...HDR.form, Origin: ORIGIN } : HDR.form, form: { client_id: clientId, grant_type: 'authorization_code', code: '{{code}}', redirect_uri: redirect, code_verifier: '{{verifier}}', scope } } },
    { id: `${p}-token-res`, from: 'entra', to: client, label: `200 ${audName || 'tokens'}`, title: 'Tokens issued', det: 'protocol',
      desc: `Entra computes <code>BASE64URL(SHA256(code_verifier))</code> and compares it with the challenge it saw earlier. They match, so it returns an access token for the resource, an ID token that tells the app who signed in, and a refresh token.`,
      res: { status: 200, statusText: 'OK', headers: HDR.json, json: { token_type: 'Bearer', scope, expires_in: 4799, ext_expires_in: 4799, access_token: `{{${tokName}}}`, refresh_token: '{{rt}}', id_token: '{{IDT}}', client_info: 'eyJ1aWQiOi...' } },
      checks: [{ name: 'PKCE: SHA256(verifier) = challenge', ok: true }, { name: 'Code unused and not expired', ok: true }, { name: 'redirect_uri identical to the authorize request', ok: true }, { name: 'Origin allowed (SPA platform)', ok: true }] },
  ];
  return short ? steps.filter((s) => !/-(state|policy)$/.test(s.id)) : steps;
}

/* ---------- 1. Authorization code + PKCE ---------- */
FLOWS.push({
  id: 'auth-code-pkce', group: 'standard', icon: '🔑', live: true,
  title: 'Authorization code + PKCE',
  subtitle: 'A user signs in to a single-page app, which calls Microsoft Graph as that user.',
  actors: ['user', 'browser', 'entra', 'graph'],
  layout: { user: [120, 90], browser: [120, 360], entra: [540, 220], graph: [880, 360] },
  variants: [
    { id: 'unknown', label: 'Personal device', desc: 'An unmanaged home PC. The user types a password and does MFA, and Conditional Access treats the session as unmanaged.' },
    { id: 'managed', label: 'Managed laptop', desc: 'An Entra joined, compliant laptop. The PRT signs the user in silently and the token carries a deviceid.' },
  ],
  brief: {
    what: 'If a user is at the keyboard, this is the flow to use. It fits web apps, SPAs, mobile and desktop alike. OAuth 2.1 makes PKCE mandatory for public clients and recommends it for everyone else.',
    prereqs: ['App registration with the <b>SPA</b> platform and redirect URI', 'Delegated permission <code>User.Read</code> with consent', 'No client secret, because a browser app can\'t keep one'],
    antiPattern: 'The <b>implicit flow</b> with <code>response_type=token</code> puts tokens in the URL, where browser history and proxy logs pick them up. <b>ROPC</b> hands the user\'s password to the app, which breaks MFA and phishing protection. Both are deprecated.',
  },
  tokens: (ctx) => ({
    AT: { label: 'Access token (aud = Graph)', ...TK.graphUser(ctx.t, { appid: ID.spa.appId, scp: 'openid profile User.Read email', appName: ID.spa.name, appidacr: '0', extra: ctx.variant === 'managed' ? { amr: ['mfa'], deviceid: 'b7e4c2a1-9f3d-4e6a-8c1b-2d5f7a9e0c34' } : {} }) },
    IDT: { label: 'ID token (who signed in)', ...TK.idToken(ctx.t, ID.spa.appId, ctx.vars.nonce) },
  }),
  steps: (ctx) => [
    { id: 'ac-start', from: 'user', to: 'browser', label: 'Click "Sign in"', title: 'User starts sign-in', det: 'human', desc: 'The user opens the app and chooses Sign in. The app has no credentials of its own.' },
    ...pkceSignInSteps('ac', { scope: SCOPE.graphUser, tokName: 'AT', audName: 'AT + ID token', device: ctx.variant }),
    { id: 'ac-graph-req', from: 'browser', to: 'graph', label: 'GET /me (Bearer AT)', title: 'Call Microsoft Graph', det: 'protocol', desc: 'The SPA puts the access token in the Authorization header. Only Graph will accept it, because its <code>aud</code> is Graph.', req: { method: 'GET', url: `${GRAPH}/v1.0/me`, headers: HDR.bearer('AT') } },
    { id: 'ac-graph-res', from: 'graph', to: 'browser', label: '200 profile', title: 'Graph returns the profile', det: 'protocol', desc: 'Graph checks the signature, the audience and the expiry, and looks for User.Read in <code>scp</code>. Then it returns the profile.', res: { status: 200, statusText: 'OK', headers: HDR.json, json: { id: ID.user.oid, displayName: ID.user.name, userPrincipalName: ID.user.upn, jobTitle: 'Procurement Lead' } }, checks: [{ name: 'Signature (JWKS)', ok: true }, { name: 'aud = https://graph.microsoft.com', ok: true }, { name: 'scp contains User.Read', ok: true }] },
  ],
});

/* ---------- 2. On-behalf-of ---------- */
FLOWS.push({
  id: 'obo', group: 'standard', icon: '🔁', live: true,
  title: 'On-behalf-of (OBO)',
  subtitle: 'An API that receives a user token swaps it for a new token to call another API as the same user.',
  actors: ['user', 'browser', 'api', 'entra', 'graph'],
  layout: { user: [110, 80], browser: [110, 330], api: [450, 330], entra: [450, 90], graph: [850, 330] },
  brief: {
    what: 'OBO carries the user through a chain of APIs. Each hop trades the token it received for a <b>new token with a new audience</b>. At every hop the caller can do only what the user can do and what that API was granted, whichever is less.',
    prereqs: [`SPA has consent for <code>${esc(SCOPE.api)}</code>`, 'The middle-tier API exposes <code>access_as_user</code> and has its own credential. Use a certificate or a federated credential, and a secret only in dev', 'API has delegated <code>User.Read</code> on Graph with consent'],
    antiPattern: '<b>Token passthrough.</b> The API forwards the token it received straight to Graph. Graph rejects it because the <code>aud</code> is wrong. The real damage happens with a downstream API that skips the audience check. It accepts the token, and your API becomes a confused deputy.',
  },
  tokens: (ctx) => ({
    Tc: { label: 'Tc: user token for Orders API', ...TK.user(ctx.t, { aud: ID.api.appId, scp: 'access_as_user', azp: ID.spa.appId }) },
    IDT: { label: 'ID token', ...TK.idToken(ctx.t, ID.spa.appId, ctx.vars.nonce) },
    CA: { label: 'client_assertion (API proves itself)', header: { alg: 'PS256', typ: 'JWT', 'x5t#S256': randStr(43) }, payload: { aud: TOKEN_EP, iss: ID.api.appId, sub: ID.api.appId, jti: ctx.vars.jti, nbf: ctx.t, iat: ctx.t, exp: ctx.t + 300 } },
    T2: { label: 'T2: Graph token for the same user (OBO result)', ...TK.graphUser(ctx.t + 2, { appid: ID.api.appId, scp: 'User.Read', appName: ID.api.name, appidacr: '2' }) },
  }),
  steps: () => [
    { id: 'obo-start', from: 'user', to: 'browser', label: 'Open "My orders"', title: 'User opens a page that needs the API', det: 'human', desc: 'The SPA needs data from the Orders API, which in turn needs the user\'s Graph profile.' },
    ...pkceSignInSteps('obo', { scope: `openid profile offline_access ${SCOPE.api}`, tokName: 'Tc', audName: 'Tc (aud = API)', short: true }),
    { id: 'obo-call-req', from: 'browser', to: 'api', label: 'GET /orders (Bearer Tc)', title: 'SPA calls the middle-tier API', det: 'protocol', desc: '<b>Tc</b> has <code>aud</code> set to the Orders API, so only this API accepts it.', req: { method: 'GET', url: 'https://orders.contoso.com/api/orders', headers: HDR.bearer('Tc') } },
    { id: 'obo-validate', from: 'api', to: 'api', label: 'Validate Tc', title: 'API validates the incoming token', det: 'protocol', desc: 'Ordinary resource-server validation. Middleware such as Microsoft.Identity.Web or jose does it for you. The API fetches the tenant\'s signing keys from the JWKS endpoint and caches them.', tok: ['Tc'],
      checks: [{ name: 'Signature valid (kid → JWKS key)', ok: true }, { name: `iss = ${ISS_V2}`, ok: true }, { name: `aud = ${ID.api.appId}`, ok: true }, { name: 'exp/nbf within clock skew', ok: true }, { name: 'scp contains access_as_user', ok: true }, { name: 'tid is an allowed tenant', ok: true }] },
    { id: 'obo-exchange-req', from: 'api', to: 'entra', label: 'POST /token OBO (assertion=Tc)', title: 'OBO exchange', det: 'protocol', desc: 'The API signs in <b>as itself</b> with a certificate-signed client assertion. It hands over Tc as the <code>assertion</code> and asks for a Graph scope.',
      why: 'Entra checks that the audience of Tc is this API\'s client ID. Hand it a token meant for some other API and you get AADSTS50013.',
      req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', client_id: ID.api.appId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{CA}}', assertion: '{{Tc}}', scope: 'https://graph.microsoft.com/User.Read', requested_token_use: 'on_behalf_of' } } },
    { id: 'obo-exchange-res', from: 'entra', to: 'api', label: '200 T2 (aud = Graph)', title: 'Entra issues T2', det: 'policy', desc: 'The new token keeps the same user in <code>oid</code>. The client in <code>appid</code> is now the API, and the audience is Graph. Entra runs Conditional Access again too, this time with the API as the client.',
      res: { status: 200, statusText: 'OK', headers: HDR.json, json: { token_type: 'Bearer', scope: 'https://graph.microsoft.com/User.Read', expires_in: 4799, access_token: '{{T2}}' } },
      checks: [{ name: 'Tc aud = requesting client (API)', ok: true }, { name: 'API credential valid (certificate)', ok: true }, { name: 'Consent API → Graph User.Read exists', ok: true }, { name: 'Conditional Access for the API as the resource', ok: true }] },
    { id: 'obo-graph-req', from: 'api', to: 'graph', label: 'GET /me (Bearer T2)', title: 'API calls Graph as the user', det: 'protocol', desc: 'The call uses T2, not Tc.', req: { method: 'GET', url: `${GRAPH}/v1.0/me?$select=displayName,userPrincipalName,id`, headers: HDR.bearer('T2') } },
    { id: 'obo-graph-res', from: 'graph', to: 'api', label: '200 profile', title: 'Graph returns data', det: 'protocol', desc: 'Graph returns only what the user can see and the API\'s delegated scopes allow.', res: { status: 200, statusText: 'OK', headers: HDR.json, json: { id: ID.user.oid, displayName: ID.user.name, userPrincipalName: ID.user.upn } } },
    { id: 'obo-call-res', from: 'api', to: 'browser', label: '200 orders', title: 'API responds to the SPA', det: 'protocol', desc: 'The API combines its own data with what it got from Graph.', res: { status: 200, statusText: 'OK', headers: HDR.json, json: { me: { displayName: ID.user.name }, orders: [{ id: 'PO-10442', amount: 1240.5, status: 'Approved' }] } } },
  ],
});
