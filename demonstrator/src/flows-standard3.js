'use strict';
/* ---------- 5. Refresh token + Continuous Access Evaluation ---------- */
FLOWS.push({
  id: 'refresh-cae', group: 'standard', icon: '⏱️', live: false,
  title: 'Refresh tokens and CAE',
  subtitle: 'How access keeps going quietly, and how Entra cuts it off within minutes when something critical happens.',
  actors: ['user', 'browser', 'entra', 'graph'],
  layout: { user: [120, 90], browser: [120, 360], entra: [540, 220], graph: [880, 360] },
  brief: {
    what: 'Nobody can recall an access token once Entra has issued it, which is why they\'re short-lived. The client quietly uses a refresh token to get new ones. <b>Continuous Access Evaluation</b> closes the gap. When something critical happens, like a disabled account, a password reset, high user risk or a new IP, Graph, Exchange and SharePoint reject the token <i>before it expires</i> and send back a claims challenge.',
    prereqs: ['A client that declares it can handle claims challenges with <code>xms_cc=cp1</code>. MSAL does this for you', 'A resource that supports CAE, such as Graph, Exchange, SharePoint or Teams', 'Strict location enforcement in Conditional Access, if you want IP changes to count'],
    antiPattern: 'Putting refresh tokens in <code>localStorage</code> or in logs. Also ignoring <code>401 insufficient_claims</code> and retrying the same call in a loop. SPA refresh tokens last 24 hours and only work from the SPA\'s origin.',
  },
  tokens: (ctx) => ({
    AT: { label: 'Access token #1 (CAE-capable, long-lived)', ...TK.graphUser(ctx.t - 4700, { appid: ID.spa.appId, scp: 'User.Read', appName: ID.spa.name, appidacr: '0' }) },
    AT2: { label: 'Access token #2 (refreshed)', ...TK.graphUser(ctx.t, { appid: ID.spa.appId, scp: 'User.Read', appName: ID.spa.name, appidacr: '0' }) },
  }),
  steps: (ctx) => {
    const claims = btoa(JSON.stringify({ access_token: { nbf: { essential: true, value: String(ctx.t + 60) } } }));
    return [
      { id: 'rt-call', from: 'browser', to: 'graph', label: 'GET /me (AT #1)', title: 'Normal call with a valid token', det: 'protocol', desc: 'While the token is valid, calls just work.', req: { method: 'GET', url: `${GRAPH}/v1.0/me`, headers: HDR.bearer('AT') } },
      { id: 'rt-ok', from: 'graph', to: 'browser', label: '200', title: 'Success', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { displayName: ID.user.name } } },
      { id: 'rt-expire', from: 'browser', to: 'browser', label: 'exp reached', title: 'Access token is close to expiry', det: 'protocol', desc: 'MSAL sees <code>exp</code> coming up and refreshes in the background. The user notices nothing.', tok: ['AT'] },
      { id: 'rt-refresh-req', from: 'browser', to: 'entra', label: 'POST /token refresh_token', title: 'Silent refresh', det: 'protocol', desc: 'The client trades the refresh token for a new access token and a fresh refresh token.', req: { method: 'POST', url: TOKEN_EP, headers: { ...HDR.form, Origin: ORIGIN }, form: { client_id: ID.spa.appId, grant_type: 'refresh_token', refresh_token: '{{rt}}', scope: 'User.Read openid profile offline_access', claims: '{"access_token":{"xms_cc":{"values":["cp1"]}}}' } } },
      { id: 'rt-refresh-res', from: 'entra', to: 'browser', label: '200 AT #2 + new RT', title: 'New tokens', det: 'policy', desc: 'Entra <b>runs Conditional Access again</b> on every refresh. Without CAE, this is where most revocations finally bite.', res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', expires_in: 86399, access_token: '{{AT2}}', refresh_token: '{{rt}}' } }, checks: [{ name: 'Refresh token valid and not revoked', ok: true }, { name: 'Conditional Access re-evaluated', ok: true }, { name: 'Client is CAE-capable (cp1): long-lived token issued', ok: true, detail: 'up to 28 h' }] },
      { id: 'rt-event', from: 'entra', to: 'graph', label: 'Critical event signal', title: 'An admin disables the user', det: 'policy', desc: 'Entra tells CAE-enabled resources about the critical event, usually within minutes. Disabled accounts, password changes, revoked sessions and high user risk all count.', why: 'Without CAE the old token keeps working until it expires, which can take an hour. With CAE the resource acts on the change within minutes.' },
      { id: 'rt-call2', from: 'browser', to: 'graph', label: 'GET /me (AT #2)', title: 'Call with a token that hasn\'t expired', det: 'protocol', desc: 'On paper the token is still valid.', req: { method: 'GET', url: `${GRAPH}/v1.0/me`, headers: HDR.bearer('AT2') } },
      { id: 'rt-401', from: 'graph', to: 'browser', label: '401 claims challenge', title: 'Graph rejects the token: CAE', det: 'policy', desc: 'Graph answers with a <b>claims challenge</b>. The client has to take these claims back to Entra. Its cached token is dead.', res: { status: 401, statusText: 'Unauthorized', headers: { 'WWW-Authenticate': `Bearer realm="", authorization_uri="${AUTHZ_EP}", error="insufficient_claims", claims="${claims}"` }, json: { error: { code: 'InvalidAuthenticationToken', message: 'Continuous access evaluation resulted in challenge with result: InteractionRequired and code: UserDisabled' } } } },
      { id: 'rt-reauth', from: 'browser', to: 'entra', label: 'Token request with claims', title: 'Client handles the challenge', det: 'protocol', desc: 'MSAL passes the claims to Entra. It tries silently first and falls back to an interactive prompt.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.spa.appId, grant_type: 'refresh_token', refresh_token: '{{rt}}', claims: atob(claims), scope: 'User.Read' } } },
      { id: 'rt-blocked', from: 'entra', to: 'browser', label: '400 invalid_grant', title: 'Access revoked', det: 'policy', desc: 'The account is disabled, so Entra refuses. Access ended even though the old token still had time left on it.', res: { status: 400, statusText: 'Bad Request', json: { error: 'invalid_grant', error_description: 'AADSTS50057: The user account is disabled.' } } },
    ];
  },
});

/* ---------- 6. Managed identity ---------- */
FLOWS.push({
  id: 'managed-identity', group: 'standard', icon: '☁️', live: false,
  title: 'Managed identity',
  subtitle: 'Azure-hosted code gets tokens without holding any secret.',
  actors: ['azapp', 'imds', 'entra', 'graph'],
  layout: { azapp: [150, 300], imds: [150, 90], entra: [540, 90], graph: [860, 300] },
  brief: {
    what: 'Azure gives the compute resource an identity, then owns and rotates its credential. Your code asks a <b>local endpoint</b> for tokens. Anything running on Azure should use this, and that includes Agent ID blueprints hosted there.',
    prereqs: ['A system-assigned or user-assigned managed identity on the App Service, Function, Container App, VM or AKS workload', 'An Azure RBAC role on the target, or Graph app roles assigned with PowerShell'],
    antiPattern: 'A client secret in app settings because it felt easier. Sharing one user-assigned identity across a dozen unrelated apps is almost as bad, since one compromise reaches all of them. An ordinary on-premises server does not have Azure IMDS: use a certificate or supported workload federation instead, unless a supported host such as Azure Arc explicitly provides a managed identity.',
  },
  tokens: (ctx) => ({ AT: { label: 'Managed identity token (aud = Graph)', ...TK.app(ctx.t, { aud: GRAPH, azp: ID.mi.clientId, oid: ID.mi.oid, roles: ['User.Read.All'], v1: true, extra: { appidacr: '2', xms_mirid: '/subscriptions/1c2d…/resourcegroups/rg-web/providers/Microsoft.Web/sites/contoso-web' } }) } }),
  steps: () => [
    { id: 'mi-need', from: 'azapp', to: 'azapp', label: 'new ManagedIdentityCredential()', title: 'Code asks the SDK for a token', det: 'protocol', desc: 'Azure.Identity checks its cache first. It only calls the local endpoint on a cache miss.' },
    { id: 'mi-req', from: 'azapp', to: 'imds', label: 'GET /metadata/identity/oauth2/token', title: 'Call the local identity endpoint', det: 'protocol', desc: 'On VMs and AKS this is IMDS at 169.254.169.254 with <code>Metadata: true</code>. App Service and Functions use <code>IDENTITY_ENDPOINT</code> and <code>X-IDENTITY-HEADER</code> instead. Only code running inside the resource can reach it.', req: { method: 'GET', url: 'http://169.254.169.254/metadata/identity/oauth2/token', query: { 'api-version': '2018-02-01', resource: 'https://graph.microsoft.com/' }, headers: { Metadata: 'true' } } },
    { id: 'mi-fwd', from: 'imds', to: 'entra', label: 'Platform credential', title: 'Platform authenticates the identity', det: 'protocol', desc: 'The Azure platform signs in to Entra with a certificate it manages and rotates itself. Your code never sees it.' },
    { id: 'mi-issue', from: 'entra', to: 'imds', label: 'Token', title: 'Entra issues a token', det: 'policy', desc: 'The roles come from app role assignments on the managed identity\'s service principal.', checks: [{ name: 'Managed identity service principal enabled', ok: true }, { name: 'App role assignment User.Read.All', ok: true }] },
    { id: 'mi-res', from: 'imds', to: 'azapp', label: '200 access_token', title: 'Token returned to the code', det: 'protocol', desc: '<code>xms_mirid</code> names the Azure resource that owns the identity.', res: { status: 200, statusText: 'OK', json: { access_token: '{{AT}}', client_id: ID.mi.clientId, expires_in: '86399', expires_on: String(nowSec() + 86399), resource: 'https://graph.microsoft.com/', token_type: 'Bearer' } } },
    { id: 'mi-call', from: 'azapp', to: 'graph', label: 'GET /users', title: 'Call the resource', det: 'protocol', desc: '', req: { method: 'GET', url: `${GRAPH}/v1.0/users?$top=1`, headers: HDR.bearer('AT') } },
    { id: 'mi-graph-res', from: 'graph', to: 'azapp', label: '200', title: 'Data returned', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { value: [{ displayName: ID.user.name }] } } },
  ],
});

/* ---------- 7. Workload identity federation ---------- */
FLOWS.push({
  id: 'wif', group: 'standard', icon: '🔗', live: false,
  title: 'Workload identity federation',
  subtitle: 'A GitHub Actions job swaps its GitHub token for an Entra token, with no secrets in GitHub.',
  actors: ['workload', 'idp', 'entra', 'arm'],
  layout: { workload: [150, 300], idp: [150, 90], entra: [540, 90], arm: [860, 300] },
  brief: {
    what: 'GitHub, Kubernetes, GCP, AWS and other Entra tenants already hand their workloads a signed token. Entra accepts that token through a <b>federated identity credential</b>, which matches issuer, subject and audience. A managed identity becomes the credential of an Agent ID blueprint the same way.',
    prereqs: [`App registration (or user-assigned managed identity) with a FIC: issuer <code>https://token.actions.githubusercontent.com</code>, subject <code>repo:${ID.wif.repo}:environment:prod</code>, audience <code>api://AzureADTokenExchange</code>`, 'Azure RBAC role on the target subscription or resource group', 'Workflow permission <code>id-token: write</code>'],
    antiPattern: 'A subject loose enough to match a whole org or any branch, or an <code>AZURE_CLIENT_SECRET</code> sitting in repo secrets. Pin the subject to the protected environment.',
  },
  tokens: (ctx) => ({
    GH: { label: 'GitHub OIDC token (external)', header: { typ: 'JWT', alg: 'RS256', kid: randStr(20) }, payload: { jti: uuid(), sub: `repo:${ID.wif.repo}:environment:prod`, aud: 'api://AzureADTokenExchange', ref: 'refs/heads/main', repository: ID.wif.repo, repository_owner: 'contoso', environment: 'prod', job_workflow_ref: `${ID.wif.repo}/.github/workflows/deploy.yml@refs/heads/main`, iss: 'https://token.actions.githubusercontent.com', nbf: ctx.t, iat: ctx.t, exp: ctx.t + 300 } },
    AT: { label: 'Entra token (aud = ARM)', ...TK.app(ctx.t + 1, { aud: 'https://management.azure.com', azp: ID.wif.appId, oid: uuid(), roles: undefined, v1: true, extra: { appidacr: '2' } }) },
  }),
  steps: () => [
    { id: 'wif-job', from: 'workload', to: 'workload', label: 'Job starts (env: prod)', title: 'Deployment job starts', det: 'protocol', desc: 'GitHub applies the environment\'s protection rules first, such as required reviewers and branch rules.' },
    { id: 'wif-oidc-req', from: 'workload', to: 'idp', label: 'Request OIDC token', title: 'Ask GitHub for an OIDC token', det: 'protocol', desc: 'The azure/login action does this for you and asks for audience <code>api://AzureADTokenExchange</code>.', req: { method: 'GET', url: 'https://pipelines.actions.githubusercontent.com/…/idtoken', query: { 'api-version': '2.0', audience: 'api://AzureADTokenExchange' }, headers: { Authorization: 'Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN' } } },
    { id: 'wif-oidc-res', from: 'idp', to: 'workload', label: 'GitHub JWT', title: 'GitHub issues a signed token', det: 'protocol', desc: 'The <code>sub</code> claim holds the repo and environment. That\'s the value Entra matches.', res: { status: 200, statusText: 'OK', json: { value: '{{GH}}' } } },
    { id: 'wif-token-req', from: 'workload', to: 'entra', label: 'POST /token (client_assertion=GitHub JWT)', title: 'Present the external token as a credential', det: 'protocol', desc: 'This is a normal client credentials request. The only difference is that the <code>client_assertion</code> is the GitHub token.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.wif.appId, grant_type: 'client_credentials', scope: 'https://management.azure.com/.default', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{GH}}' } } },
    { id: 'wif-verify', from: 'entra', to: 'idp', label: 'OIDC discovery + JWKS', title: 'Entra verifies the external signature', det: 'protocol', desc: 'Entra fetches and caches GitHub\'s public keys, then checks the signature and expiry.', req: { method: 'GET', url: 'https://token.actions.githubusercontent.com/.well-known/openid-configuration' } },
    { id: 'wif-match', from: 'entra', to: 'entra', label: 'Match FIC', title: 'Match the federated identity credential', det: 'policy', desc: 'Issuer, subject and audience must match a federated credential on the app <b>exactly</b>. Flexible credential expressions are the one exception.', tok: ['GH'], checks: [{ name: 'iss = https://token.actions.githubusercontent.com', ok: true }, { name: `sub = repo:${ID.wif.repo}:environment:prod`, ok: true }, { name: 'aud = api://AzureADTokenExchange', ok: true }, { name: 'Signature and expiry', ok: true }] },
    { id: 'wif-token-res', from: 'entra', to: 'workload', label: '200 ARM token', title: 'Entra token issued', det: 'protocol', desc: 'It\'s short-lived, and GitHub stores nothing.', res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', expires_in: 3599, access_token: '{{AT}}' } } },
    { id: 'wif-call', from: 'workload', to: 'arm', label: 'PUT deployment', title: 'Deploy', det: 'protocol', desc: 'ARM checks Azure RBAC on the target scope.', req: { method: 'PUT', url: 'https://management.azure.com/subscriptions/…/resourcegroups/rg-orders/providers/Microsoft.Resources/deployments/orders-api?api-version=2024-03-01', headers: HDR.bearer('AT') } },
    { id: 'wif-arm-res', from: 'arm', to: 'workload', label: '201 Created', title: 'Deployment accepted', det: 'policy', desc: 'The job has <i>Contributor</i> on rg-orders, so ARM accepts.', res: { status: 201, statusText: 'Created', json: { properties: { provisioningState: 'Accepted' } } } },
  ],
});
