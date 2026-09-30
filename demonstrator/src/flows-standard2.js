'use strict';
/* ---------- 3. Client credentials ---------- */
FLOWS.push({
  id: 'client-credentials', group: 'standard', icon: '🗄️', live: true,
  title: 'Client credentials (app-only)',
  subtitle: 'A background service calls an API as itself, with no user present.',
  actors: ['daemon', 'entra', 'graph'],
  layout: { daemon: [150, 300], entra: [500, 110], graph: [850, 300] },
  variants: [
    { id: 'certificate', label: 'Certificate (client assertion)', desc: 'The app signs a short-lived JWT with its private key. Entra only ever holds the public half. Use this one.' },
    { id: 'secret', label: 'Client secret', desc: 'A shared password. It leaks easily and people forget to rotate it. Keep it to dev and test.' },
  ],
  brief: {
    what: 'This is for daemons, scheduled jobs and service-to-service calls. The token stands for the <b>application</b>, so it carries <code>roles</code> for the application permissions and no <code>scp</code>. The app can do whatever an admin granted it. No user is involved, so no user-level check limits it.',
    prereqs: ['An app registration with a certificate, a federated credential or a secret', 'An application permission such as <code>User.Read.All</code>, with <b>admin consent</b>', 'The scope <code>{resource}/.default</code>'],
    antiPattern: 'Granting a daemon something like tenant-wide <code>Mail.ReadWrite</code> when a delegated flow would work, or when RBAC for Applications or Sites.Selected could scope it to a few mailboxes or sites. App-only tokens skip every user-level access check.',
  },
  tokens: (ctx) => ({
    CA: { label: 'client_assertion signed with the app certificate', header: { alg: 'RS256', typ: 'JWT', x5t: randStr(27) }, payload: { aud: TOKEN_EP, iss: ID.daemon.appId, sub: ID.daemon.appId, jti: ctx.vars.jti, nbf: ctx.t, iat: ctx.t, exp: ctx.t + 300 } },
    AT: { label: 'App-only access token (aud = Graph)', ...TK.app(ctx.t, { aud: GRAPH, azp: ID.daemon.appId, oid: ID.daemon.spOid, roles: ['User.Read.All'], v1: true, extra: { app_displayname: ID.daemon.name, appidacr: ctx.variant === 'secret' ? '1' : '2' } }) },
  }),
  steps: (ctx) => {
    const cert = ctx.variant !== 'secret';
    const credForm = cert
      ? { client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{CA}}' }
      : { client_secret: 'secret' };
    return [
      { id: 'cc-trigger', from: 'daemon', to: 'daemon', label: 'Scheduler fires', title: 'Job starts', det: 'protocol', desc: 'A timer or a queue message starts the job. Nobody is around to sign in, and nobody sees a consent prompt.' },
      { id: 'cc-build-cred', from: 'daemon', to: 'daemon', label: cert ? 'Sign client assertion' : 'Load secret', title: cert ? 'Build and sign a client assertion' : 'Load the client secret', det: 'protocol',
        desc: cert ? 'The app builds a JWT addressed to the token endpoint, with its own client ID as issuer and subject, a unique <code>jti</code> and a 5 minute lifetime. It signs it with the <b>private key</b> from Key Vault or the certificate store.' : 'The app reads the shared secret from configuration or Key Vault.',
        why: cert ? 'The private key never leaves the app, and each assertion works once and dies in minutes. A managed identity or federated credential is better still, because then there\'s no key to lose.' : 'Anyone holding this string can be the app until the secret expires. They turn up in repos, build logs and Teams chats all the time.',
        tok: cert ? ['CA'] : [] },
      { id: 'cc-token-req', from: 'daemon', to: 'entra', label: 'POST /token client_credentials', title: 'Request an app-only token', det: 'protocol', desc: 'The scope is always <code>/.default</code>. It means every application permission an admin has granted this app on the resource. You can\'t ask for individual scopes here.',
        req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.daemon.appId, scope: 'https://graph.microsoft.com/.default', ...credForm, grant_type: 'client_credentials' } } },
      { id: 'cc-policy', from: 'entra', to: 'entra', label: 'Verify credential + app roles', title: 'Entra checks the credential and assignments', det: 'policy', desc: 'Entra checks the credential, then looks up which Graph app roles an admin has assigned to this service principal. Conditional Access for workload identities can block the request here too.',
        checks: cert ? [{ name: 'Assertion signature matches the uploaded certificate (x5t)', ok: true }, { name: 'Assertion aud = token endpoint, not expired', ok: true }, { name: 'jti not used before (no replay)', ok: true }, { name: 'App role assignments → roles claim', ok: true, detail: 'User.Read.All' }]
          : [{ name: 'Secret hash matches and hasn\'t expired', ok: true }, { name: 'App role assignments → roles claim', ok: true, detail: 'User.Read.All' }] },
      { id: 'cc-token-res', from: 'entra', to: 'daemon', label: '200 app token', title: 'App-only token issued', det: 'protocol', desc: 'Look for <code>idtyp=app</code>, a <code>roles</code> claim and no <code>scp</code>. There\'s no refresh token either. When this token expires, the app asks again.',
        res: { status: 200, statusText: 'OK', headers: HDR.json, json: { token_type: 'Bearer', expires_in: 3599, ext_expires_in: 3599, access_token: '{{AT}}' } } },
      { id: 'cc-graph-req', from: 'daemon', to: 'graph', label: 'GET /users (Bearer)', title: 'Call Graph as the app', det: 'protocol', desc: 'The daemon reads directory data with its application permission.', req: { method: 'GET', url: `${GRAPH}/v1.0/users?$top=1&$select=id,displayName`, headers: HDR.bearer('AT') } },
      { id: 'cc-graph-res', from: 'graph', to: 'daemon', label: '200 users', title: 'Graph returns data', det: 'protocol', desc: 'Graph authorizes on <code>roles</code> alone. There\'s no user to check.', res: { status: 200, statusText: 'OK', headers: HDR.json, json: { value: [{ id: ID.user.oid, displayName: ID.user.name }] } } },
    ];
  },
});

/* ---------- 4. Device code ---------- */
function dcVariant(ctx, steps) {
  if (ctx.variant !== 'blocked') return steps;
  const cut = steps.findIndex((s) => s.id === 'dc-poll-req-2');
  return [...steps.slice(0, cut),
    { id: 'dc-policy', from: 'entra', to: 'entra', label: 'Authentication flows policy', title: 'Conditional Access sees a device code flow', det: 'policy', desc: 'The policy targets the authentication flow itself. It doesn\'t matter that the user passed MFA, because the flow is the risk.',
      checks: [{ name: 'Authentication flow = device code', ok: false, detail: 'Policy "Block device code flow" applies' }, { name: 'User or app excluded from the policy', ok: false }] },
    { ...steps[cut] },
    { id: 'dc-token-res', from: 'entra', to: 'device', label: '400 blocked', title: 'No tokens for the device', det: 'policy', status: 'error', desc: 'The device polls and gets a Conditional Access error. On the phone, the user sees "You cannot access this right now".',
      res: { status: 400, statusText: 'Bad Request', headers: HDR.json, json: { error: 'invalid_grant', error_description: 'AADSTS53003: Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.' } } },
  ];
}
FLOWS.push({
  id: 'device-code', group: 'standard', icon: '📟', live: true,
  title: 'Device code',
  subtitle: 'Sign in on a device with no browser by finishing sign-in on a phone or laptop.',
  actors: ['user', 'device', 'entra', 'graph'],
  layout: { user: [140, 90], device: [140, 360], entra: [560, 220], graph: [880, 360] },
  variants: [
    { id: 'allowed', label: 'Allowed', desc: 'The flow is allowed for this user and app, as for a real CLI user.' },
    { id: 'blocked', label: 'Blocked by Conditional Access', desc: 'A policy blocks the device code flow. The attacker\'s phishing attempt dies at the token endpoint.' },
  ],
  brief: {
    what: 'Built for CLIs, TVs, IoT gear and SSH sessions. The device shows a code. The user signs in somewhere else, and meanwhile the device polls until its tokens are ready.',
    prereqs: ['An app registration with <b>Allow public client flows</b> turned on', 'Delegated permissions with consent', 'A Conditional Access policy that allows the device code flow for these users and apps'],
    antiPattern: '<b>Device code phishing.</b> An attacker starts the flow on their own machine and talks a user into typing the code. Block the flow with the Conditional Access authentication flows condition everywhere you don\'t need it.',
  },
  tokens: (ctx) => ({ AT: { label: 'Access token (aud = Graph)', ...TK.graphUser(ctx.t + 20, { appid: ID.spa.appId, scp: 'openid profile User.Read email', appName: 'Contoso CLI', appidacr: '0' }) } }),
  steps: (ctx) => dcVariant(ctx, [
    { id: 'dc-start', from: 'user', to: 'device', label: 'contoso login', title: 'User runs the CLI', det: 'human', desc: 'The device can\'t show a sign-in page.' },
    { id: 'dc-code-req', from: 'device', to: 'entra', label: 'POST /devicecode', title: 'Ask for a device code', det: 'protocol', desc: 'This is a public client, so it sends no secret.', req: { method: 'POST', url: `${AUTHORITY}/oauth2/v2.0/devicecode`, headers: HDR.form, form: { client_id: ID.spa.appId, scope: SCOPE.graphUser } } },
    { id: 'dc-code-res', from: 'entra', to: 'device', label: 'user_code + device_code', title: 'Entra returns codes', det: 'protocol', desc: 'The <code>user_code</code> is for the person. The device keeps the <code>device_code</code> secret and polls with it.',
      res: { status: 200, statusText: 'OK', headers: HDR.json, json: { user_code: '{{userCode}}', device_code: '{{deviceCode}}', verification_uri: 'https://microsoft.com/devicelogin', expires_in: 900, interval: 5, message: 'To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code {{userCode}} to authenticate.' } } },
    { id: 'dc-show-code', from: 'device', to: 'user', label: 'Show code', title: 'Device shows the code', det: 'human', desc: 'The user reads the code and the URL.', kv: { user_code: '{{userCode}}', verification_uri: 'https://microsoft.com/devicelogin' } },
    { id: 'dc-poll-req', from: 'device', to: 'entra', label: 'POST /token (poll)', title: 'Device polls', det: 'protocol', desc: 'The device asks again every <code>interval</code> seconds.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: ID.spa.appId, device_code: '{{deviceCode}}' } } },
    { id: 'dc-poll-res', from: 'entra', to: 'device', label: '400 authorization_pending', title: 'Not yet', det: 'protocol', status: 'pending', desc: 'The user hasn\'t finished yet, so the device keeps polling.', res: { status: 400, statusText: 'Bad Request', headers: HDR.json, json: { error: 'authorization_pending', error_description: 'AADSTS70016: OAuth 2.0 device flow error. Authorization is pending. Continue polling.' } } },
    { id: 'dc-user-signin', from: 'user', to: 'entra', label: 'Enter code, sign in + MFA', title: 'User signs in on a second device', det: 'human', desc: 'On a phone or laptop the user opens microsoft.com/devicelogin, types the code, sees <b>which app</b> is asking and signs in with MFA.', why: 'The user has to confirm they started this sign-in. Nothing else in the protocol stops device code phishing.' },
    { id: 'dc-poll-req-2', from: 'device', to: 'entra', label: 'POST /token (poll)', title: 'Next poll', det: 'protocol', desc: 'Same request as the first poll.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: ID.spa.appId, device_code: '{{deviceCode}}' } } },
    { id: 'dc-token-res', from: 'entra', to: 'device', label: '200 tokens', title: 'Tokens issued to the device', det: 'protocol', desc: 'The device now holds user tokens, including a refresh token.', res: { status: 200, statusText: 'OK', headers: HDR.json, json: { token_type: 'Bearer', scope: 'openid profile User.Read email', expires_in: 4799, access_token: '{{AT}}', refresh_token: '{{rt}}', id_token: '…' } } },
    { id: 'dc-graph-req', from: 'device', to: 'graph', label: 'GET /me', title: 'Call Graph', det: 'protocol', desc: 'A normal delegated call.', req: { method: 'GET', url: `${GRAPH}/v1.0/me`, headers: HDR.bearer('AT') } },
    { id: 'dc-graph-res', from: 'graph', to: 'device', label: '200 profile', title: 'Profile returned', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', headers: HDR.json, json: { displayName: ID.user.name, userPrincipalName: ID.user.upn } } },
  ]),
});
