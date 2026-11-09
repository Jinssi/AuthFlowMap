'use strict';
/* =====================================================================
   FLOW DEFINITION: confidential web app, authorization code + app credential
   ===================================================================== */
{
  const WEB = 'https://portal.contoso.com';
  const CB = `${WEB}/signin-oidc`;
  const SCOPES = 'openid profile offline_access User.Read';
  const flow = {
    id: 'web-app', group: 'standard', icon: '🏛️', live: true,
    title: 'Web app sign-in (confidential client)',
    subtitle: 'A server-side web app proves its own identity with a certificate or secret, and the user\'s identity with the authorization code.',
    actors: ['user', 'browser', 'webapp', 'entra', 'graph'],
    layout: { user: [110, 80], browser: [110, 360], webapp: [480, 360], entra: [480, 80], graph: [860, 360] },
    variants: [
      { id: 'certificate', label: 'Certificate', desc: 'The app signs a short-lived client assertion with its private key. Use this, or a managed identity federated credential, in production.' },
      { id: 'secret', label: 'Client secret', desc: 'The app sends a shared secret. Fine for a lab, risky anywhere else.' },
    ],
    brief: {
      what: 'This is the classic web app: ASP.NET, Spring, Express or Django running on a server. Two identities meet in one flow. The <b>user</b> proves who they are to Entra and comes back with an authorization code. The <b>app</b> then redeems that code and proves who <i>it</i> is with a certificate or a secret, so a stolen code is useless to anyone else. The tokens stay in the server\'s token cache. The browser only ever holds a session cookie.<br><br>The server can be <b>on-premises</b>; hosting does not change this OAuth contract. A synchronized AD user can authenticate through <a href="#flow/hybrid-signin">PHS, PTA or federation</a>. An old IWA app that does not implement OIDC needs a different bridge, such as <a href="#flow/onprem-app-proxy">Application Proxy with KCD</a>.',
      prereqs: ['App registration with the <b>Web</b> platform and a redirect URI such as /signin-oidc', 'A credential on the app: a certificate or a federated credential in production, a secret in a lab', 'Delegated permissions such as User.Read', 'A server-side session store and token cache. MSAL and Microsoft.Identity.Web provide both'],
      antiPattern: 'Sending the access token down to the browser "so the JavaScript can call the API too", or registering the redirect under the SPA platform to skip the credential. Either way the app loses the protection it has as a confidential client. Also avoid the old implicit or hybrid flow just to get an ID token.',
      verify: 'Live mode runs this with a real app registration. The popup is the web app: the local server plays the web app back end, redeems the code with its own secret or certificate and keeps the tokens.',
    },
    tokens: (ctx) => {
      const cert = ctx.variant !== 'secret';
      return {
        IDT: { label: 'ID token: who signed in, for the web app', ...TK.idToken(ctx.t, ID.webapp.appId, ctx.vars.nonce) },
        AT: { label: 'Access token for Graph, held by the server', ...TK.graphUser(ctx.t, { appid: ID.webapp.appId, scp: 'openid profile User.Read email', appName: ID.webapp.name, appidacr: cert ? '2' : '1' }) },
        CA: { label: 'client_assertion signed with the app certificate', header: { alg: 'RS256', typ: 'JWT', x5t: randStr(27) }, payload: { aud: TOKEN_EP, iss: ID.webapp.appId, sub: ID.webapp.appId, jti: ctx.vars.jti, nbf: ctx.t, iat: ctx.t, exp: ctx.t + 300 } },
      };
    },
    steps: (ctx) => {
      const cert = ctx.variant !== 'secret';
      const cred = cert ? { client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{CA}}' } : { client_secret: 'secret' };
      const authUrl = `${AUTHZ_EP}?client_id=${ID.webapp.appId}&response_type=code&redirect_uri=${encodeURIComponent(CB)}&response_mode=query&scope=${encodeURIComponent(SCOPES)}&state={{state}}&nonce={{nonce}}&code_challenge={{challenge}}&code_challenge_method=S256`;
      return [
        { id: 'wa-start', from: 'user', to: 'browser', label: `Opens ${WEB}`, title: 'User opens the web app', det: 'human', desc: 'Nobody is signed in yet.' },
        { id: 'wa-req', from: 'browser', to: 'webapp', label: 'GET /', title: 'Browser asks the server for a page', det: 'protocol', desc: 'The server sees no session cookie, so it starts a sign-in.', req: { method: 'GET', url: `${WEB}/` } },
        { id: 'wa-pkce', from: 'webapp', to: 'webapp', label: 'State, nonce and PKCE', title: 'Server prepares the sign-in', det: 'protocol', desc: 'The server makes <code>state</code>, <code>nonce</code> and a PKCE verifier, and keeps them in a short-lived, HttpOnly correlation cookie or its own session store. OAuth 2.1 recommends PKCE for confidential clients too.', kv: { state: '{{state}}', nonce: '{{nonce}}', code_challenge: '{{challenge}}', code_verifier: 'kept on the server' } },
        { id: 'wa-redirect', from: 'webapp', to: 'browser', label: '302 to /authorize', title: 'Server redirects the browser to Entra', det: 'protocol', desc: 'The server never shows a login form of its own. It sends the browser to Entra.', res: { status: 302, statusText: 'Found', headers: { Location: authUrl, 'Set-Cookie': '.AspNetCore.Correlation=…[masked]; HttpOnly; Secure; SameSite=None' } } },
        { id: 'wa-authz', from: 'browser', to: 'entra', label: 'GET /authorize', title: 'Browser goes to Entra', det: 'protocol', desc: 'Same authorize request as a SPA, but the redirect URI is registered under the Web platform. That tells Entra the code may only be redeemed by a client with a credential.', req: { method: 'GET', url: AUTHZ_EP, query: { client_id: ID.webapp.appId, response_type: 'code', redirect_uri: CB, response_mode: 'query', scope: SCOPES, state: '{{state}}', nonce: '{{nonce}}', code_challenge: '{{challenge}}', code_challenge_method: 'S256' } } },
        { id: 'wa-signin', from: 'entra', to: 'user', label: 'Sign-in + MFA', title: 'User signs in at Entra', det: 'human', desc: 'The user deals with Entra only. The web app never sees the password or the MFA.' },
        { id: 'wa-policy', from: 'entra', to: 'entra', label: 'CA + consent', title: 'Conditional Access and consent', det: 'policy', desc: 'Entra runs Conditional Access for this user and this app, and checks consent for the scopes.', checks: [{ name: 'Conditional Access policies satisfied', ok: true }, { name: 'Consent for openid profile User.Read', ok: true }, { name: 'Redirect URI registered on the Web platform', ok: true }] },
        { id: 'wa-code', from: 'entra', to: 'browser', label: '302 ?code&state', title: 'Code comes back through the browser', det: 'protocol', desc: 'The code travels through the browser. On its own it\'s useless, because redeeming it needs the app\'s credential and the PKCE verifier. Many frameworks use <code>response_mode=form_post</code> so the code never lands in the address bar.', res: { status: 302, statusText: 'Found', headers: { Location: `${CB}?code={{code}}&state={{state}}` } } },
        { id: 'wa-callback', from: 'browser', to: 'webapp', label: 'GET /signin-oidc?code', title: 'Browser delivers the code to the server', det: 'protocol', desc: '', req: { method: 'GET', url: `${CB}?code={{code}}&state={{state}}`, headers: { Cookie: '.AspNetCore.Correlation=…[masked]' } } },
        { id: 'wa-state', from: 'webapp', to: 'webapp', label: 'Check state + cookie', title: 'Server matches the callback to its own request', det: 'protocol', desc: 'The state must match, and the correlation cookie proves this is the same browser that started the sign-in.', checks: [{ name: 'state matches a pending sign-in', ok: true }, { name: 'Correlation cookie matches this browser', ok: true }, { name: 'Not expired and not used before', ok: true }] },
        { id: 'wa-token-req', from: 'webapp', to: 'entra', label: `POST /token (code + ${cert ? 'certificate' : 'secret'})`, title: 'Server redeems the code and proves who it is', det: 'protocol',
          desc: cert ? 'This is where the app authenticates itself. It sends the code and the verifier <b>plus a client assertion signed with its private key</b>. The call goes server to server, so no browser ever sees it.' : 'This is where the app authenticates itself. It sends the code and the verifier <b>plus its client secret</b>, server to server.',
          why: 'Two separate proofs arrive together. The code proves the user signed in. The credential proves the right app is asking. Steal one and you still don\'t have the other.',
          req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.webapp.appId, grant_type: 'authorization_code', code: '{{code}}', redirect_uri: CB, code_verifier: '{{verifier}}', scope: SCOPES, ...cred } } },
        { id: 'wa-token-res', from: 'entra', to: 'webapp', label: '200 ID + access + refresh', title: 'Entra issues tokens to the server', det: 'policy', desc: 'Look at <code>appidacr</code> in the access token. It says how the app proved itself: 1 for a secret, 2 for a certificate. A SPA would show 0.',
          res: { status: 200, statusText: 'OK', headers: HDR.json, json: { token_type: 'Bearer', scope: SCOPES, expires_in: 4799, access_token: '{{AT}}', refresh_token: '{{rt}}', id_token: '{{IDT}}' } },
          checks: [{ name: cert ? 'Client assertion signature matches the uploaded certificate' : 'Client secret valid and not expired', ok: true }, { name: 'PKCE: SHA256(verifier) = challenge', ok: true }, { name: 'Code issued to this client_id and redirect_uri', ok: true }] },
        { id: 'wa-idtoken', from: 'webapp', to: 'webapp', label: 'Validate ID token', title: 'Server validates the ID token', det: 'protocol', desc: 'The ID token tells the app who signed in. The app checks it before it trusts a single claim.', tok: ['IDT'], checks: [{ name: 'Signature (JWKS)', ok: true }, { name: 'iss = this tenant', ok: true }, { name: `aud = ${ID.webapp.appId}, this app`, ok: true }, { name: 'nonce matches the one the server sent', ok: true }, { name: 'exp in the future', ok: true }] },
        { id: 'wa-session', from: 'webapp', to: 'browser', label: 'Set session cookie', title: 'Browser gets a session, not tokens', det: 'protocol', desc: 'The server stores the tokens in its token cache and hands the browser a session cookie. The refresh token never leaves the server.', res: { status: 302, statusText: 'Found', headers: { Location: '/', 'Set-Cookie': '.AspNetCore.Cookies=…[masked]; HttpOnly; Secure; SameSite=Lax' } } },
        { id: 'wa-graph-req', from: 'webapp', to: 'graph', label: 'GET /me (Bearer AT)', title: 'Server calls Graph as the user', det: 'protocol', desc: 'The server takes the token from its cache. When it expires, the server refreshes it with its credential.', req: { method: 'GET', url: `${GRAPH}/v1.0/me`, headers: HDR.bearer('AT') } },
        { id: 'wa-graph-res', from: 'graph', to: 'webapp', label: '200 profile', title: 'Graph returns the profile', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { displayName: ID.user.name, userPrincipalName: ID.user.upn } } },
        { id: 'wa-page', from: 'webapp', to: 'browser', label: '200 page', title: 'Server renders the page', det: 'protocol', desc: 'The browser gets HTML. It never saw a token.', res: { status: 200, statusText: 'OK', headers: { 'Content-Type': 'text/html' }, text: `<h1>Hello ${ID.user.name}</h1>` } },
      ];
    },
  };
  FLOWS.splice(FLOWS.findIndex((f) => f.id === 'auth-code-pkce') + 1, 0, flow);
}
