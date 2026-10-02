'use strict';
/* =====================================================================
   ACTORS: every component that can appear in the architecture or a flow.
   ===================================================================== */
const ACTORS = {
  user: {
    icon: '👤', name: ID.user.name, role: 'Human user', zone: 'people',
    desc: 'The person who signs in, does MFA and gives consent. In delegated flows every token is issued for this user. The app can do only what the user can do and what the app was granted.',
    facts: ['Proves who they are to Entra ID, never to the app', 'Consent means "this app may do X for me"', 'Entra runs Conditional Access for this user at every sign-in'],
  },
  browser: {
    icon: '🌐', name: 'Client app (SPA)', role: 'Public client in a browser', zone: 'people',
    desc: `${ID.spa.name} is a single-page app. A browser can't keep a secret, so it signs users in with authorization code + PKCE. It gets tokens for APIs and sends them as a Bearer header.`,
    facts: ['A public client with no secret', 'PKCE proves that the app that started the sign-in is the one finishing it', 'Keeps tokens in memory, not in localStorage'],
  },
  device: {
    icon: '📟', name: 'CLI / TV device', role: 'Input-constrained public client', zone: 'people',
    desc: 'A CLI, TV or IoT device with no usable browser. It asks the user to finish signing in on a second device. That\'s the device code flow.',
    facts: ['Polls the token endpoint until the user finishes', 'Phishers like this flow. Limit it with the Conditional Access authentication flows condition'],
  },
  api: {
    icon: '⚙️', name: ID.api.name, role: 'Middle-tier API · confidential client', zone: 'apps',
    desc: 'A web API that validates the tokens it receives, which makes it a resource server. When it needs another API it becomes a confidential client and uses OBO to call it as the same user.',
    facts: ['Validates the signature, iss, aud, exp and scp', 'Never forwards the incoming token downstream', 'Signs in to Entra with a certificate, a federated credential or a secret'],
  },
  webapp: {
    icon: '🏛️', name: 'Web app (server)', role: 'Confidential client · has a credential', zone: 'apps',
    desc: 'A server-side web app such as ASP.NET, Java or Node. It signs users in with the authorization code flow and proves its own identity to Entra with a certificate or a secret. The tokens stay in its server-side cache, and the browser only gets a session cookie.',
    facts: ['Two identities in one flow: the app with its credential, the user with the code', 'appidacr 1 means a secret, 2 means a certificate', 'Tokens never reach the browser'],
  },
  daemon: {
    icon: '🗄️', name: ID.daemon.name, role: 'Daemon · confidential client', zone: 'apps',
    desc: 'A background service that runs with nobody signed in. It gets app-only tokens through the client credentials grant, and everything it can do comes from its application permissions.',
    facts: ['Its token has roles and no scp', 'idtyp = app', 'Give it a certificate, managed identity or federated credential, not a secret'],
  },
  azapp: {
    icon: '☁️', name: 'Azure-hosted app', role: 'Uses a managed identity', zone: 'apps',
    desc: `${ID.mi.name} runs on App Service, Functions, Container Apps, a VM or AKS. It gets tokens from the local managed identity endpoint, so there are no secrets to store or rotate.`,
    facts: ['Azure owns and rotates the credential', 'System-assigned or user-assigned', 'Can also act as the federated credential behind an Agent ID blueprint'],
  },
  workload: {
    icon: '🔧', name: 'External workload', role: 'GitHub Actions / Kubernetes pod', zone: 'apps',
    desc: 'A workload outside Azure that already holds a token from its own platform, such as a GitHub OIDC token or a Kubernetes service account token. It swaps that for an Entra token.',
    facts: ['Nothing secret is stored in GitHub or the cluster', 'Entra trusts it through a federated identity credential that matches issuer, subject and audience'],
  },
  idp: {
    icon: '🪪', name: 'External IdP', role: 'GitHub OIDC / K8s issuer', zone: 'identity',
    desc: 'The external platform\'s identity provider. It issues short-lived OIDC tokens, and Entra accepts them through a federated identity credential.',
    facts: ['Entra fetches its signing keys through OIDC discovery', 'The subject has to match exactly, for example repo:org/repo:environment:prod'],
  },
  imds: {
    icon: '📍', name: 'Managed identity endpoint', role: 'IMDS 169.254.169.254', zone: 'identity',
    desc: 'A local token endpoint on Azure compute that nothing outside the machine can reach. It hands out tokens for the attached managed identity.',
    facts: ['Every request needs the header Metadata: true', 'It caches tokens, so most calls never reach Entra'],
  },
  agent: {
    icon: '🤖', name: 'Agent host', role: 'Agent ID blueprint + agent identity', zone: 'agents',
    desc: `Where the AI agent runs. It holds the credential of ${ID.blueprint.name} and uses it to get tokens for its own agent identity, ${ID.agent.name}. It can act on its own, for a signed-in user, or as its own agent user account.`,
    facts: ['Only the blueprint holds a credential. Agent identities can\'t', 'Tokens come from a two-step exchange. First a parent token via fmi_path, then the agent token', 'Every agent instance has its own sub and appid in the logs'],
  },
  llm: {
    icon: '🧠', name: 'LLM', role: 'Language model (non-deterministic)', zone: 'agents',
    desc: 'The model picks which tool to call and what arguments to pass. It never sees a credential. Once it has chosen, the host handles authentication with ordinary protocol code.',
    facts: ['Decides which tool and which arguments', 'Never decides identity, scopes or consent', 'Treat its output as untrusted input'],
  },
  mcpclient: {
    icon: '🧩', name: 'MCP host / client', role: 'VS Code, Copilot Studio and others', zone: 'agents',
    desc: 'The MCP host runs the model and one MCP client per server. Over HTTP it acts as an OAuth 2.1 client to protected MCP servers.',
    facts: ['Finds the authorization server through Protected Resource Metadata', 'Uses PKCE and asks for tokens whose audience is that one MCP server'],
  },
  mcpserver: {
    icon: '🛠️', name: ID.mcp.name, role: 'MCP server · OAuth resource server', zone: 'resources',
    desc: 'Offers tools, resources and prompts over Streamable HTTP. It only accepts tokens issued for itself, and it calls downstream APIs with an OBO token of its own.',
    facts: ['Answers with 401 and a WWW-Authenticate header that carries resource_metadata', 'Rejects tokens whose aud is another resource', 'Never passes the client token on to other APIs'],
  },
  orchestrator: {
    icon: '🎛️', name: ID.orchestrator.name, role: 'Agent identity A', zone: 'agents',
    desc: 'The first agent in a chain. It breaks a task into pieces and calls specialist agents, and each of those is a protected resource in its own right.',
    facts: ['Gets a fresh token for every hop', 'Keeps the user in sub and oid when it acts for the user'],
  },
  subagent: {
    icon: '🧾', name: ID.subagent.name, role: 'Agent identity B', zone: 'agents',
    desc: 'A specialist agent that other agents call like an API. It validates the token it receives and runs its own exchange before touching its data sources.',
    facts: ['Has its own audience and scopes', 'The audit trail shows the user, the orchestrator and the finance agent'],
  },
  entra: {
    icon: '🔐', name: 'Microsoft Entra ID', role: 'Authorization server · STS', zone: 'identity',
    desc: 'Signs in users and workloads, runs Conditional Access and consent checks, and issues signed tokens. The endpoints in play are /authorize, /token, /devicecode, discovery and JWKS.',
    facts: ['Signs every token. APIs check the signature with its public keys from JWKS', 'Applies Conditional Access, consent and app role assignments', 'Writes a sign-in log entry for every token it issues'],
  },
  graph: {
    icon: '📇', name: 'Microsoft Graph', role: 'Resource API', zone: 'resources',
    desc: 'The Microsoft 365 API, standing in here for any protected resource. It checks the audience, then scp for delegated calls or roles for app-only calls.',
    facts: ['aud = https://graph.microsoft.com', 'A delegated call gets only what both the user and the app\'s scopes allow'],
  },
  downstream: {
    icon: '🏭', name: ID.downstream.name, role: 'Line-of-business API', zone: 'resources',
    desc: 'An internal ERP or CRM API that agents and MCP servers call. Callers need a token with this API as the audience.',
    facts: ['aud = api://contoso-erp', 'Can read the xms_* claims to tell agent traffic from human traffic'],
  },
  arm: {
    icon: '🏗️', name: 'Azure Resource Manager', role: 'Azure control plane API', zone: 'resources',
    desc: 'The management API for Azure resources and the usual target of deployment pipelines. Access comes from Azure RBAC role assignments on the service principal.',
    facts: ['aud = https://management.azure.com', 'Authorizes with Azure RBAC, not with roles in the token'],
  },
  pc: {
    icon: '💻', name: 'Managed laptop', role: 'Entra joined · WAM + PRT in TPM', zone: 'people',
    desc: 'A company laptop joined to Entra ID and enrolled in Intune. At Windows sign-in it gets a Primary Refresh Token bound to the TPM. Browsers and apps use it for single sign-on and to prove which device they run on.',
    facts: ['The PRT key never leaves the TPM', 'Sign-ins from this device carry a device ID and compliance state', 'Conditional Access can require exactly this kind of device'],
  },
  attacker: {
    icon: '🕵️', name: 'Attacker', role: 'Phishing proxy · own device', zone: 'people',
    desc: 'Runs an attacker-in-the-middle phishing site that relays the real Entra sign-in page. It captures the password, lets the user finish MFA, then keeps the session cookie and replays it from its own machine.',
    facts: ['Push, SMS and one-time codes can all be relayed', 'Passkeys and Windows Hello can\'t, because they check the site\'s real origin', 'Token protection makes a stolen token useless on another device'],
  },
  intune: {
    icon: '🛡️', name: 'Microsoft Intune', role: 'Device compliance', zone: 'identity',
    desc: 'Manages the device and decides whether it\'s compliant: encrypted, patched, has a PIN, runs Defender. It writes that state onto the device object in Entra, where Conditional Access reads it.',
    facts: ['Compliance is a device property Conditional Access can require', 'An unknown device has no compliance state at all'],
  },
  risk: {
    icon: '📈', name: 'ID Protection', role: 'Risk engine', zone: 'identity',
    desc: 'Scores every sign-in and every user for risk, using signals such as unfamiliar location, impossible travel, leaked credentials and token anomalies. Conditional Access policies act on those scores.',
    facts: ['Sign-in risk is about this one sign-in. User risk is about the account', 'Users can fix their own risk with MFA or a secure password change', 'Needs Entra ID P2'],
  },
  foundry: {
    icon: '🧭', name: 'Foundry agent', role: 'Foundry Agent Service · project managed identity', zone: 'agents',
    desc: `${ID.foundry.name} runs in Foundry Agent Service. It reaches a Foundry IQ knowledge base through an MCP tool, and the project's managed identity authenticates that call. The user's identity travels separately, in a header the caller supplies on every request.`,
    facts: ['The project connection uses ProjectManagedIdentity with audience https://search.azure.com/', 'The managed identity needs Search Index Data Reader, which only lets it query', 'Per-user trimming only happens if the user token reaches the knowledge base'],
  },
  search: {
    icon: '🔎', name: 'Foundry IQ knowledge base', role: 'Azure AI Search · agentic retrieval', zone: 'resources',
    desc: `The knowledge base ${ID.search.kb} lives in Azure AI Search. It plans the query, searches its knowledge sources and returns grounded passages with citations. On indexed sources it filters results against the ACLs, RBAC scopes and sensitivity labels it ingested. On remote sources it calls the source as the user.`,
    facts: ['Two credentials per request: the caller in Authorization, the user in x-ms-query-source-authorization', 'Expands the user\'s groups through Microsoft Graph at query time', 'A knowledge source created without permission ingestion returns everything to everyone'],
  },
  workiq: {
    icon: '💼', name: 'Work IQ', role: 'Microsoft 365 intelligence · MCP, A2A, REST', zone: 'resources',
    desc: 'The context layer behind Microsoft 365 Copilot, offered to your own agents over MCP, A2A and REST. It reads mail, files, meetings and chats only as the signed-in user, and a tenant policy layer decides which paths and operations agents may use.',
    facts: [`Scope ${ID.workiq.uri}/WorkIQAgent.Ask is delegated only and needs admin consent`, 'Write operations are off by default in the tenant policy', 'Every request is checked again against the user\'s Microsoft 365 permissions'],
  },
  m365: {
    icon: '🗂️', name: 'Microsoft 365 content', role: 'SharePoint, OneDrive, Exchange, Teams + Purview', zone: 'resources',
    desc: 'The documents, mail and chats that Copilot and Work IQ ground on. Their permissions and Purview sensitivity labels decide what comes back. Nothing in the AI layer widens them.',
    facts: ['The semantic index respects existing permissions', 'An encrypted item needs both VIEW and EXTRACT usage rights before Copilot returns it', 'A site shared with everyone in the company is visible to everyone\'s Copilot'],
  },
};

const ZONES = [
  { id: 'people', label: 'People & devices', x: 20, w: 200 },
  { id: 'apps', label: 'Apps & workloads', x: 240, w: 210 },
  { id: 'agents', label: 'Agents & AI', x: 470, w: 230 },
  { id: 'identity', label: 'Identity plane', x: 720, w: 210 },
  { id: 'resources', label: 'Resources', x: 950, w: 210 },
];
const ARCH_POS = {
  user: [120, 100], browser: [120, 215], pc: [120, 330], device: [120, 445], attacker: [120, 590],
  api: [345, 100], webapp: [345, 210], daemon: [345, 320], azapp: [345, 430], workload: [345, 560],
  agent: [585, 110], llm: [585, 230], mcpclient: [585, 350], orchestrator: [585, 470], subagent: [585, 590], foundry: [585, 710],
  risk: [825, 100], entra: [825, 215], intune: [825, 330], idp: [825, 470], imds: [825, 590],
  graph: [1055, 90], mcpserver: [1055, 195], downstream: [1055, 300], arm: [1055, 405], search: [1055, 515], workiq: [1055, 620], m365: [1055, 725],
};
const ARCH_EDGES = [
  ['user', 'browser'], ['user', 'device'], ['browser', 'api'], ['browser', 'webapp'], ['webapp', 'entra'], ['webapp', 'graph'], ['browser', 'entra'], ['device', 'entra'],
  ['api', 'entra'], ['api', 'graph'], ['daemon', 'entra'], ['daemon', 'graph'], ['azapp', 'imds'], ['azapp', 'graph'],
  ['workload', 'idp'], ['workload', 'entra'], ['idp', 'entra'], ['imds', 'entra'],
  ['agent', 'entra'], ['agent', 'graph'], ['agent', 'llm'], ['browser', 'agent'],
  ['mcpclient', 'mcpserver'], ['mcpclient', 'entra'], ['mcpclient', 'llm'], ['mcpserver', 'entra'], ['mcpserver', 'graph'], ['mcpserver', 'downstream'],
  ['orchestrator', 'subagent'], ['orchestrator', 'entra'], ['subagent', 'entra'],   ['subagent', 'downstream'],
  ['pc', 'entra'], ['intune', 'entra'], ['risk', 'entra'], ['attacker', 'browser'],
  ['webapp', 'foundry'], ['foundry', 'llm'], ['foundry', 'entra'], ['foundry', 'search'], ['search', 'entra'], ['search', 'graph'], ['search', 'workiq'],
  ['mcpclient', 'workiq'], ['workiq', 'entra'], ['workiq', 'm365'],
];

/* =====================================================================
   CLAIM DICTIONARY: explanations shown next to decoded tokens.
   key = highlight as the important claim to point at.
   ===================================================================== */
const CLAIM_INFO = {
  typ: 'Token type (JWT).', alg: 'Signature algorithm. Entra signs with RS256.', kid: 'Key ID. Tells the API which JWKS public key checks the signature.', x5t: 'Thumbprint of the signing certificate.', nonce: 'A header nonce shows up on Graph tokens. It means only Graph can validate the token, so your API shouldn\'t try.',
  aud: { d: 'Audience. The single API this token is for. An API must reject a token with any other aud.', key: true },
  iss: { d: 'Issuer. The Entra tenant that issued and signed the token.', key: true },
  iat: 'Issued at (epoch seconds).', nbf: 'Not valid before.', exp: { d: 'Expiry. Access tokens usually last 60 to 90 minutes, longer when CAE is on.', key: true },
  aio: 'Entra-internal. Ignore it.', rh: 'Entra-internal. Ignore it.', uti: 'Token ID. Search the sign-in logs for it.', ver: 'Token version, 1.0 or 2.0. The API picks it with requestedAccessTokenVersion.',
  azp: { d: 'Authorized party. The client app or agent identity that asked for the token. v2 tokens use this name.', key: true },
  appid: { d: 'Client app ID. v1 tokens use this name for azp.', key: true },
  azpacr: 'How the client proved itself. 0 is a public client, 1 a secret, 2 a certificate or federated credential.', appidacr: 'The v1 name for azpacr. 0 is a public client, 1 a secret, 2 a certificate or federated credential.',
  idp: 'Identity provider that authenticated the subject.',
  idtyp: { d: 'Identity type. "user" for delegated tokens, "app" for app-only. Decide user versus app from this claim and nothing else.', key: true },
  name: 'Display name of the user.', preferred_username: 'Sign-in name, for display only. Never use it for authorization.', upn: 'User principal name, in v1 tokens.',
  oid: { d: 'Object ID of the subject, whether that\'s a user, a service principal or an agent identity. Authorize on this.', key: true },
  sub: { d: 'Subject, unique per app. In agent tokens it\'s either the agent identity or the user.', key: true },
  tid: { d: 'Tenant ID. A multi-tenant API should allow-list it.', key: true },
  scp: { d: 'The delegated scopes the user consented to. Only user tokens have it.', key: true },
  roles: { d: 'Application permissions, or app roles assigned to the user.', key: true },
  amr: { d: 'How the user authenticated, as a list such as pwd and mfa. Key-based methods add values such as rsa. Run a flow in Live mode to see what your own sign-in produces.', key: true }, deviceid: { d: 'The Entra device ID. Only present when the sign-in came from a registered or joined device that proved itself, for example with a PRT.', key: true }, ipaddr: 'The IP address Entra saw at sign-in.', acr: 'Authentication context class.', acrs: { d: 'Authentication contexts the user satisfied, such as c1. An API checks it before a sensitive action and sends a claims challenge when it\'s missing.', key: true },
  sid: 'Session ID.', wids: 'Directory role template IDs.', xms_cc: 'Client capabilities. "cp1" means the client can handle CAE claims challenges.',
  xms_ftd: 'Entra-internal. Ignore it.', xms_idrel: 'How the subject relates to the resource tenant. 1 is a member user and 7 a service principal, among others.',
  xms_act_fct: { d: 'Actor facets, meaning facts about the actor in azp. 11 is AgentIdentity and 13 is AgentIDUser. This is how an API knows an agent is calling.', key: true },
  xms_sub_fct: { d: 'Subject facets, meaning facts about the subject. 13 marks an agent\'s user account.', key: true },
  xms_tnt_fct: 'Tenant facets.',
  xms_par_app_azp: { d: 'The parent app of the authorized party, which is the agent identity blueprint. Log it, but don\'t authorize on it.', key: true },
  xms_mirid: 'Managed identity resource ID (Azure resource path).',
  code_challenge: 'SHA-256 hash of the PKCE verifier.',
  jti: 'Unique ID that stops the assertion being replayed.',
  'x5t#S256': 'SHA-256 thumbprint of the certificate that signed this assertion.',
  repository: 'GitHub repository.', environment: 'GitHub environment.', job_workflow_ref: 'Workflow that ran.',
  'kubernetes.io': 'Kubernetes service account binding.',
  act: 'Actor claim (RFC 8693): the party acting for the subject.',
};

/* =====================================================================
   TOKEN BUILDERS for Simulated mode (claims mirror real Entra tokens).
   ===================================================================== */
const TK = {
  hdr: (extra = {}) => ({ typ: 'JWT', alg: 'RS256', kid: 'HS23b7Do7TcaU1Rh5LdbcGXFaQ', ...extra }),
  times: (t, life = 4799) => ({ iat: t, nbf: t, exp: t + life }),
  user(t, { aud, scp, azp, azpacr = '0', extra = {} }) {
    return {
      header: TK.hdr(),
      payload: { aud, iss: ISS_V2, ...TK.times(t), aio: randStr(40), azp, azpacr, idtyp: 'user', name: ID.user.name, oid: ID.user.oid, preferred_username: ID.user.upn, rh: '1.AR8A' + randStr(30), scp, sid: uuid(), sub: randStr(43), tid: ID.tid, uti: randStr(22), ver: '2.0', ...extra },
    };
  },
  graphUser(t, { appid, scp, appName, appidacr = '1', extra = {} }) {
    return {
      header: TK.hdr({ nonce: randStr(43) }),
      payload: { aud: GRAPH, iss: `https://sts.windows.net/${ID.tid}/`, ...TK.times(t), acct: 0, acr: '1', aio: randStr(40), amr: ['pwd', 'mfa'], app_displayname: appName, appid, appidacr, idtyp: 'user', ipaddr: '203.0.113.24', name: ID.user.name, oid: ID.user.oid, scp, sub: randStr(43), tid: ID.tid, unique_name: ID.user.upn, upn: ID.user.upn, uti: randStr(22), ver: '1.0', xms_cc: ['cp1'], ...extra },
    };
  },
  app(t, { aud, azp, oid, roles, v1 = false, extra = {} }) {
    const base = v1
      ? { aud, iss: `https://sts.windows.net/${ID.tid}/`, ...TK.times(t, 3599), aio: randStr(40), appid: azp, appidacr: extra.appidacr ?? '2', idp: `https://sts.windows.net/${ID.tid}/`, idtyp: 'app', oid, roles, sub: oid, tid: ID.tid, uti: randStr(22), ver: '1.0' }
      : { aud, iss: ISS_V2, ...TK.times(t, 3599), aio: randStr(40), azp, azpacr: extra.azpacr ?? '2', idtyp: 'app', oid, roles, sub: oid, tid: ID.tid, uti: randStr(22), ver: '2.0' };
    delete extra.appidacr; delete extra.azpacr;
    return { header: TK.hdr(v1 ? { nonce: randStr(43) } : {}), payload: { ...base, ...extra } };
  },
  idToken(t, azp, nonce) {
    return { header: TK.hdr(), payload: { aud: azp, iss: ISS_V2, ...TK.times(t, 3600), name: ID.user.name, nonce, oid: ID.user.oid, preferred_username: ID.user.upn, sub: randStr(43), tid: ID.tid, ver: '2.0' } };
  },
};
