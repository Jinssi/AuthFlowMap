'use strict';
/* =====================================================================
   FLOW DEFINITIONS: IQ and grounded agents (Work IQ, Foundry IQ, oversharing)
   Sources: Work IQ MCP overview, permissions and policy governance; Foundry IQ connect;
   Azure AI Search query-time ACL enforcement, retrieve and Work IQ knowledge source docs.
   ===================================================================== */
{
  const WIQ_SCOPE = `${ID.workiq.uri}/WorkIQAgent.Ask`;
  const SEARCH_AUD = 'https://search.azure.com';
  const KB_URL = `${ID.search.host}/knowledgebases/${ID.search.kb}`;
  const KB_MCP = `${KB_URL}/mcp?api-version=${ID.search.api}`;
  const KB_RETRIEVE = `${KB_URL}/retrieve?api-version=${ID.search.api}`;
  const userTok = (t, aud, scp, azp, extra = {}) => TK.user(t, { aud, scp, azp, azpacr: '2', extra: { amr: ['pwd', 'mfa'], ...extra } });
  const RAG_APP = '0d1c2b3a-4e5f-4a6b-8c7d-9e0f1a2b3c4d';
  const miTok = (t, aud, oid, label) => ({ label, ...TK.app(t, { aud, azp: uuid(), oid, roles: undefined, extra: { xms_mirid: '/subscriptions/…/providers/Microsoft.Search/searchServices/contoso-search' } }) });

  /* ---------- Work IQ over MCP ---------- */
  FLOWS.push({
    id: 'workiq-mcp', group: 'iq', icon: '💼', live: false,
    preview: 'Work IQ MCP and its tenant policy controls are new. Check availability in your region.',
    title: 'Work IQ over MCP',
    subtitle: 'An agent signs the user in, calls the Work IQ MCP server and gets only what that user may already see. Tenant policy then blocks a write the model asked for.',
    actors: ['user', 'llm', 'mcpclient', 'entra', 'workiq', 'm365'],
    layout: { user: [110, 80], llm: [110, 380], mcpclient: [420, 230], entra: [420, 50], workiq: [720, 230], m365: [960, 380] },
    brief: {
      what: 'Work IQ is the Microsoft 365 context layer behind Copilot, opened up to your own agents. Over MCP it has ten generic tools such as <code>fetch</code>, <code>do_action</code> and <code>ask</code>, which work on paths like <code>/me/messages</code>. Four layers decide each call. <b>Entra</b> authenticates the user and the app. The <b>OAuth permission</b> <code>WorkIQAgent.Ask</code> lets the app use Work IQ at all. The <b>user\'s own Microsoft 365 permissions</b> limit what comes back. A <b>tenant policy layer</b> written in Rego allows or denies the path and operation. Work IQ never sees more than the user already can. It also finds everything the user can see, overshared sites included.',
      prereqs: ['A Global Administrator has enabled Work IQ for the tenant and set up billing', `An app registration (public client here) with the delegated permission <code>${WIQ_SCOPE}</code> and admin consent. There\'s no application permission, so no app-only access`, 'The Work IQ MCP server is allowed in the Microsoft 365 admin center under Agents > Tools', 'The tenant policy: read-only unless an admin explicitly allows writes'],
      antiPattern: 'Treating Work IQ or Copilot as a permissions fix. It applies the permissions you already have, so a finance site shared with "Everyone except external users" shows up in every user\'s answers. Clean up oversharing first, with data access governance reports and Restricted Content Discovery, and label sensitive content.',
      verify: 'Simulated only. The token request and the tool calls follow the documented shapes. The policy-denied error body is illustrative, because the docs only say to surface it and not to retry.',
    },
    tokens: (ctx) => ({
      Twiq: { label: 'Twiq: user token for Work IQ', ...userTok(ctx.t + 1, ID.workiq.appId, 'WorkIQAgent.Ask', ID.wiqClient.appId, { azpacr: '0' }) },
      IDT: { label: 'ID token for the client', ...TK.idToken(ctx.t + 1, ID.wiqClient.appId, ctx.vars.nonce) },
    }),
    steps: () => [
      { id: 'wq-ask', from: 'user', to: 'mcpclient', label: '"What did finance decide on the Q3 budget?"', title: 'User asks the agent', det: 'human', desc: 'The agent host could be Copilot Studio, Foundry, GitHub Copilot CLI or your own app. The flow is the same.' },
      { id: 'wq-init', from: 'mcpclient', to: 'workiq', label: 'POST /mcp (no token)', title: 'First call without a token', det: 'protocol', desc: 'The client knows only the server URL.', req: { method: 'POST', url: ID.workiq.mcp, headers: HDR.json, json: { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', clientInfo: { name: 'contoso-agent' } } } } },
      { id: 'wq-401', from: 'workiq', to: 'mcpclient', label: '401 + resource_metadata', title: 'Work IQ points at its metadata', det: 'protocol', desc: 'Work IQ publishes Protected Resource Metadata, so the client discovers the authorization server the same way as in the MCP authorization tab.', res: { status: 401, statusText: 'Unauthorized', headers: { 'WWW-Authenticate': 'Bearer resource_metadata="https://workiq.svc.cloud.microsoft/.well-known/oauth-protected-resource"' } } },
      ...pkceSignInSteps('wq', { client: 'mcpclient', scope: `${WIQ_SCOPE} offline_access`, tokName: 'Twiq', audName: 'Twiq (aud = Work IQ)', short: true, clientId: ID.wiqClient.appId, redirect: 'http://localhost:8080/callback' }),
      { id: 'wq-consent', from: 'entra', to: 'entra', label: 'Admin consent present?', title: 'Entra checks the Work IQ grant', det: 'policy', desc: '<code>WorkIQAgent.Ask</code> needs admin consent, so a user can\'t grant it alone. Conditional Access runs for this user as for any other app.', checks: [{ name: 'Admin consent for WorkIQAgent.Ask', ok: true }, { name: 'Conditional Access for the user', ok: true }, { name: 'Application permission requested', ok: true, detail: 'None exists. Work IQ is delegated only' }] },
      { id: 'wq-plan', from: 'mcpclient', to: 'llm', label: 'Prompt + 10 Work IQ tools', title: 'Host gives the model the tool list', det: 'protocol', desc: 'The model sees tool names and schemas. It never sees Twiq.' },
      { id: 'wq-pick', from: 'llm', to: 'mcpclient', label: 'tool_call: ask', title: 'Model picks the ask tool', det: 'ai', desc: '<code>ask</code> hands the question to Microsoft 365 Copilot, which grounds it on the user\'s mail, files and meetings.' },
      { id: 'wq-call', from: 'mcpclient', to: 'workiq', label: 'tools/call ask (Bearer Twiq)', title: 'Tool call with the user token', det: 'protocol', desc: '', req: { method: 'POST', url: ID.workiq.mcp, headers: { ...HDR.json, ...HDR.bearer('Twiq'), 'Mcp-Session-Id': '{{sid}}' }, json: { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'ask', arguments: { question: 'What did finance decide on the Q3 budget?' } } } } },
      { id: 'wq-layers', from: 'workiq', to: 'workiq', label: 'Token + policy', title: 'Work IQ runs its first layers', det: 'policy', desc: 'Policy approval isn\'t the last word. The data itself is checked against the user\'s permissions in the next step.', tok: ['Twiq'], checks: [{ name: `aud = ${ID.workiq.appId} (Work IQ)`, ok: true }, { name: 'scp contains WorkIQAgent.Ask', ok: true }, { name: 'idtyp = user', ok: true }, { name: 'Tenant policy: ask is a read', ok: true }] },
      { id: 'wq-ground', from: 'workiq', to: 'm365', label: 'Ground as Alex', title: 'Grounding with the user\'s permissions', det: 'policy', desc: 'Copilot searches the semantic index and Microsoft Graph <b>as the user</b>. Items the user can\'t open never become candidates.', checks: [{ name: 'Finance Q3 minutes (Teams meeting Alex attended)', ok: true }, { name: 'Budget workbook on the Finance site, shared with Procurement', ok: true }, { name: 'Board pack: user has no access', ok: false, detail: 'Trimmed. Never reaches the model' }] },
      { id: 'wq-labels', from: 'm365', to: 'workiq', label: '2 items, labels checked', title: 'Sensitivity labels apply', det: 'policy', desc: 'For encrypted items the user needs both VIEW and EXTRACT usage rights. The answer inherits the most restrictive label among its sources.', checks: [{ name: 'Budget workbook: Confidential, EXTRACT granted', ok: true }, { name: 'Salary review: Highly Confidential, VIEW only', ok: false, detail: 'No EXTRACT right, so Copilot can\'t use it' }] },
      { id: 'wq-res', from: 'workiq', to: 'mcpclient', label: 'Answer + citations', title: 'Tool result', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { jsonrpc: '2.0', id: 4, result: { content: [{ type: 'text', text: 'Finance cut the Q3 travel budget by 15% and froze new SaaS contracts. Sources: Q3 budget review (meeting), Q3 budget.xlsx' }] } } } },
      { id: 'wq-pick2', from: 'llm', to: 'mcpclient', label: 'tool_call: do_action /me/sendMail', title: 'Model wants to send a summary mail', det: 'ai', desc: 'The user never asked for a mail. A prompt hidden in a document could cause the same thing.' },
      { id: 'wq-approve', from: 'mcpclient', to: 'user', label: 'Approve send?', title: 'Host asks the user', det: 'human', desc: 'Good hosts ask before anything that sends or changes data. Here the user clicks Approve anyway.' },
      { id: 'wq-send', from: 'mcpclient', to: 'workiq', label: 'tools/call do_action', title: 'Write request reaches Work IQ', det: 'protocol', desc: '', req: { method: 'POST', url: ID.workiq.mcp, headers: { ...HDR.json, ...HDR.bearer('Twiq') }, json: { jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'do_action', arguments: { path: '/me/sendMail', body: { message: { subject: 'Q3 budget summary', toRecipients: ['finance-all@contoso.com'] } } } } } } },
      { id: 'wq-deny', from: 'workiq', to: 'mcpclient', label: 'Denied by tenant policy', title: 'Policy blocks the write', det: 'policy', status: 'error', desc: 'Mutations are off by default. The user is signed in and the app holds the permission, yet the call fails, because policy is checked separately. The client should show this as a governance decision and not retry.', checks: [{ name: 'Operation: action on /me/sendMail', ok: false, detail: 'Write operations not allowed in this tenant' }], res: { status: 200, statusText: 'OK', json: { jsonrpc: '2.0', id: 5, error: { code: -32001, message: 'Denied by tenant policy: write operations are disabled for Work IQ MCP' } } } },
      { id: 'wq-show', from: 'mcpclient', to: 'user', label: 'Answer, mail not sent', title: 'User gets the answer', det: 'protocol', desc: 'The answer covers only what Alex could already open, and the mail never went out.' },
    ],
  });

  /* ---------- Foundry IQ knowledge base with query-time trimming ---------- */
  FLOWS.push({
    id: 'foundry-iq', group: 'iq', icon: '🔎', live: false,
    preview: 'Query-time ACL and RBAC enforcement and the knowledge base MCP endpoint are in preview (API 2026-08-01-preview).',
    title: 'Foundry IQ knowledge base',
    subtitle: 'A Foundry agent queries a knowledge base with its own managed identity and passes the user\'s token alongside, so Azure AI Search returns only documents that user may read.',
    actors: ['user', 'webapp', 'foundry', 'llm', 'entra', 'search', 'graph'],
    layout: { user: [100, 80], webapp: [100, 360], foundry: [420, 360], llm: [420, 600], entra: [420, 80], search: [760, 360], graph: [760, 80] },
    brief: {
      what: 'Foundry IQ knowledge bases run on Azure AI Search. Every retrieve call carries <b>two identities</b>. The <code>Authorization</code> header is the caller, here the Foundry project\'s managed identity, and its RBAC role lets it query at all. The <code>x-ms-query-source-authorization</code> header is the <b>user</b>, a token for <code>https://search.azure.com</code>. Search reads the user\'s <code>oid</code>, expands their groups through Microsoft Graph and builds a security filter from the ACLs, RBAC scopes and labels it ingested. A document is returned if any of those filters lets the user in.',
      prereqs: ['Knowledge sources created with <code>ingestionPermissionOptions</code>, so permission metadata lands in the index', 'Foundry project managed identity has <b>Search Index Data Reader</b> on the search service', 'A project connection of type RemoteTool with ProjectManagedIdentity, pointing at the knowledge base MCP endpoint', 'The agent\'s MCP tool takes the user token as a structured input and puts it in the header on every call', 'For remote SharePoint sources, each user needs a Microsoft 365 Copilot license'],
      antiPattern: 'Leaving the user token out. Learn pages disagree on the result: the Search docs say ACL-protected content is dropped, the Foundry and retrieve docs say permission-enabled sources come back unfiltered. Don\'t rely on either. Send the token on every call and test with two users who should see different things.',
      verify: 'Simulated only. Header names, roles and the retrieve shape follow the docs. ACL changes reach the index only when the indexer runs or you reingest, so allow for some lag.',
    },
    tokens: (ctx) => ({
      Tq: { label: 'Tq: user token for Azure AI Search (query identity)', ...userTok(ctx.t + 1, SEARCH_AUD, 'user_impersonation', ID.webapp.appId) },
      Tapp: { label: 'Web app token for Foundry', ...TK.app(ctx.t + 1, { aud: 'https://ai.azure.com', azp: ID.webapp.appId, oid: uuid(), roles: undefined }) },
      Tmi: miTok(ctx.t + 2, SEARCH_AUD, ID.foundry.miOid, 'Tmi: project managed identity token for Search'),
    }),
    steps: () => [
      { id: 'fq-ask', from: 'user', to: 'webapp', label: '"Can contractors fly business class?"', title: 'Signed-in user asks a question', det: 'human', desc: 'Alex already signed in to the web app, as in the web app tab. The server holds Alex\'s refresh token.' },
      { id: 'fq-tq-req', from: 'webapp', to: 'entra', label: 'POST /token scope=search', title: 'Web app gets a user token for Search', det: 'protocol', desc: 'The web app uses Alex\'s refresh token and its own credential to get a token whose audience is Azure AI Search. This token grants nothing by itself. It only says who the user is.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.webapp.appId, grant_type: 'refresh_token', refresh_token: '{{rt}}', scope: `${SEARCH_AUD}/.default`, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '…[masked]' } } },
      { id: 'fq-tq-res', from: 'entra', to: 'webapp', label: 'Tq (aud = search)', title: 'User token for the query', det: 'policy', desc: 'Conditional Access runs again, so a blocked or risky user doesn\'t get one.', tok: ['Tq'], res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', scope: `${SEARCH_AUD}/user_impersonation`, expires_in: 4799, access_token: '{{Tq}}' } } },
      { id: 'fq-agent', from: 'webapp', to: 'foundry', label: 'Run agent (user_token = Tq)', title: 'Web app calls the agent', det: 'protocol', desc: 'The app authenticates to Foundry as itself and passes Tq as a structured input. The agent definition maps that input into the MCP tool header. Body abbreviated.', req: { method: 'POST', url: `${ID.foundry.project}/openai/v1/responses`, headers: { ...HDR.json, ...HDR.bearer('Tapp') }, json: { agent: 'policy-assistant', input: 'Can contractors fly business class?', structured_inputs: { user_token: '{{Tq}}' } } } },
      { id: 'fq-plan', from: 'foundry', to: 'llm', label: 'Prompt + knowledge_base_retrieve', title: 'Agent asks the model', det: 'protocol', desc: 'The model sees the tool. It never sees Tq.' },
      { id: 'fq-pick', from: 'llm', to: 'foundry', label: 'tool_call: knowledge_base_retrieve', title: 'Model calls the knowledge base', det: 'ai', desc: '' },
      { id: 'fq-mi', from: 'foundry', to: 'entra', label: 'Managed identity → Search', title: 'Project identity gets its own token', det: 'protocol', desc: 'The project connection uses ProjectManagedIdentity with audience <code>https://search.azure.com/</code>. Foundry gets the token for you. No key is stored.', kv: { authType: 'ProjectManagedIdentity', category: 'RemoteTool', audience: 'https://search.azure.com/' } },
      { id: 'fq-mi-res', from: 'entra', to: 'foundry', label: 'Tmi (app token)', title: 'Managed identity token', det: 'protocol', desc: '', tok: ['Tmi'] },
      { id: 'fq-call', from: 'foundry', to: 'search', label: 'tools/call + 2 tokens', title: 'Retrieve with two identities', det: 'protocol', desc: '<code>Authorization</code> is the caller. <code>x-ms-query-source-authorization</code> is the user.', why: 'Splitting them means the agent can\'t widen access by being powerful, and the user can\'t query the index without an app the admin approved.', req: { method: 'POST', url: KB_MCP, headers: { ...HDR.json, ...HDR.bearer('Tmi'), 'x-ms-query-source-authorization': '{{Tq}}' }, json: { jsonrpc: '2.0', id: 7, method: 'tools/call', params: { name: 'knowledge_base_retrieve', arguments: { request: 'contractor business class travel policy' } } } } },
      { id: 'fq-authz', from: 'search', to: 'search', label: 'Check caller + user', title: 'Search checks both tokens', det: 'policy', desc: '', tok: ['Tq'], checks: [{ name: 'Caller has Search Index Data Reader', ok: true, detail: `Project managed identity ${ID.foundry.miOid.slice(0, 8)}…` }, { name: 'Query token valid, aud = https://search.azure.com', ok: true }, { name: `User oid = ${ID.user.oid.slice(0, 8)}…`, ok: true }] },
      { id: 'fq-groups', from: 'search', to: 'graph', label: 'Expand groups for oid', title: 'Group membership from Graph', det: 'protocol', desc: 'Search resolves the user\'s transitive groups at query time, so a membership change applies on the next query. If Graph is down, Search returns a 5xx instead of half-filtered results.' },
      { id: 'fq-groups-res', from: 'graph', to: 'search', label: '2 groups', title: 'Groups returned', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { value: [{ id: ID.groups.procurement, displayName: 'Procurement' }, { id: ID.groups.allStaff, displayName: 'All staff' }] } } },
      { id: 'fq-filter', from: 'search', to: 'search', label: 'Security filter', title: 'Results trimmed to what Alex may read', det: 'policy', desc: 'Search adds a filter on the userIds, groupIds and rbacScope fields to every query. The planner, the semantic ranker and the model only ever see what survives.', checks: [{ name: 'Travel policy 2026.pdf: groupIds has All staff', ok: true }, { name: 'Contractor handbook: groupIds has Procurement', ok: true }, { name: 'Executive travel exceptions: groupIds = HR only', ok: false, detail: 'Filtered out before ranking' }] },
      { id: 'fq-res', from: 'search', to: 'foundry', label: '2 references', title: 'Grounded passages back to the agent', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { jsonrpc: '2.0', id: 7, result: { content: [{ type: 'text', text: '[ref 0] Contractors book economy for flights under 6 hours… [ref 1] Business class needs VP approval…' }] } } } },
      { id: 'fq-answer', from: 'llm', to: 'foundry', label: 'Answer with citations', title: 'Model writes the answer', det: 'ai', desc: 'It can only cite what Search returned.' },
      { id: 'fq-back', from: 'foundry', to: 'webapp', label: 'Agent response', title: 'Agent returns the answer', det: 'protocol', desc: 'Citations point at the source documents, so the user can open them with their own access.' },
      { id: 'fq-show', from: 'webapp', to: 'user', label: 'Answer + 2 sources', title: 'User sees the answer', det: 'protocol', desc: 'Someone in HR asking the same question would also get the exceptions document. Same agent, same index, different user, different answer.' },
    ],
  });

  /* ---------- Foundry IQ + Work IQ knowledge source ---------- */
  FLOWS.push({
    id: 'foundry-workiq', group: 'iq', icon: '🔗', live: false,
    preview: 'The Work IQ knowledge source is in preview (API 2026-08-01-preview). The docs warn it may perform actions, not just read.',
    title: 'Foundry IQ + Work IQ (OBO)',
    subtitle: 'One knowledge base mixes indexed documents with live Microsoft 365 data. Azure AI Search exchanges the user\'s assertion for a Work IQ token, so Microsoft 365 is still read as the user.',
    actors: ['user', 'webapp', 'entra', 'search', 'workiq', 'm365'],
    layout: { user: [100, 80], webapp: [100, 360], entra: [440, 80], search: [440, 360], workiq: [780, 360], m365: [780, 80] },
    brief: {
      what: 'A Work IQ knowledge source isn\'t indexed. Search calls Work IQ live, on the user\'s behalf. The client sends a <b>user assertion</b>, a token for <i>your own</i> connector app registration with scope <code>access_as_user</code>, in <code>x-ms-query-work-iq-source-authorization</code>. Search authenticates as that connector app through a <b>federated credential</b> on its managed identity, so there\'s no secret. It then runs an <b>OBO</b> exchange for a delegated Work IQ token. The user stays the subject the whole way down.',
      prereqs: [`Connector app registration ${ID.wiqApp.name}: exposes <code>access_as_user</code> and holds delegated <code>WorkIQAgent.Ask</code> with admin consent`, 'Federated credential on the connector app: issuer = the tenant\'s v2.0 endpoint, subject = the search service managed identity principal ID, audience = api://AzureADTokenExchange', 'Client app has the delegated permission access_as_user on the connector app', 'Work IQ enabled for the tenant, and each querying user assigned to the Work IQ billing plan'],
      antiPattern: 'Pointing the Work IQ knowledge source at a broad audience while it\'s in preview. The docs warn it may use Work IQ capabilities that take actions, so limit it to trusted apps and users. Also wrong: putting the assertion in <code>x-ms-query-source-authorization</code>. Work IQ uses its own header, and the call fails with 400.',
      verify: 'Simulated only. The app setup, headers and status codes follow the Work IQ knowledge source article.',
    },
    tokens: (ctx) => ({
      Ta: { label: 'Ta: user assertion for the connector app', ...userTok(ctx.t + 1, ID.wiqApp.appId, 'access_as_user', ID.webapp.appId) },
      Tsvc: { label: 'Web app token for Azure AI Search', ...TK.app(ctx.t + 1, { aud: SEARCH_AUD, azp: ID.webapp.appId, oid: uuid(), roles: undefined }) },
      Tfic: miTok(ctx.t + 2, 'api://AzureADTokenExchange', ID.search.miOid, 'Search managed identity token used as a client assertion'),
      Twiq: { label: 'Twiq: delegated Work IQ token held by Search', ...userTok(ctx.t + 3, ID.workiq.appId, 'WorkIQAgent.Ask', ID.wiqApp.appId) },
    }),
    steps: () => [
      { id: 'fw-ask', from: 'user', to: 'webapp', label: '"Where is project Falcon at?"', title: 'User asks across documents and mail', det: 'human', desc: 'The knowledge base has an indexed project library and a Work IQ source for the user\'s mail and meetings.' },
      { id: 'fw-a-req', from: 'webapp', to: 'entra', label: 'scope=api://connector/access_as_user', title: 'Get the user assertion', det: 'protocol', desc: 'The audience is your connector app, not Work IQ. That keeps the client from holding a Work IQ token at all.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.webapp.appId, grant_type: 'refresh_token', refresh_token: '{{rt}}', scope: `api://${ID.wiqApp.appId}/access_as_user`, client_assertion: '…[masked]' } } },
      { id: 'fw-a-res', from: 'entra', to: 'webapp', label: 'Ta (aud = connector app)', title: 'Assertion issued', det: 'policy', desc: '', tok: ['Ta'], res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', scope: `api://${ID.wiqApp.appId}/access_as_user`, expires_in: 4799, access_token: '{{Ta}}' } } },
      { id: 'fw-retrieve', from: 'webapp', to: 'search', label: 'POST /retrieve + Work IQ header', title: 'Retrieve with the Work IQ header', det: 'protocol', desc: 'Work IQ can take 40 to 60 seconds, so the request allows 120.', req: { method: 'POST', url: KB_RETRIEVE, headers: { ...HDR.json, ...HDR.bearer('Tsvc'), 'x-ms-query-work-iq-source-authorization': '{{Ta}}' }, json: { messages: [{ role: 'user', content: [{ type: 'text', text: 'Where is project Falcon at?' }] }], knowledgeSourceParams: [{ knowledgeSourceName: 'my-workiq-ks', kind: 'workIQ', includeReferences: true, includeReferenceSourceData: true }], includeActivity: true, maxRuntimeInSeconds: 120 } } },
      { id: 'fw-check', from: 'search', to: 'search', label: 'Check assertion', title: 'Search checks the assertion first', det: 'protocol', desc: 'A missing or malformed header gets a 400 before anything else happens.', tok: ['Ta'], checks: [{ name: `aud = ${ID.wiqApp.appId.slice(0, 8)}… (connector app)`, ok: true }, { name: 'scp contains access_as_user', ok: true }, { name: 'oid and tid present', ok: true }] },
      { id: 'fw-fic', from: 'search', to: 'search', label: 'MI token for token exchange', title: 'Search gets a managed identity token', det: 'protocol', desc: 'The search service\'s managed identity gets a token for <code>api://AzureADTokenExchange</code>. That token stands in for a client secret.', tok: ['Tfic'] },
      { id: 'fw-obo', from: 'search', to: 'entra', label: 'OBO (assertion = Ta)', title: 'Search runs OBO as the connector app', det: 'protocol', desc: 'Same OBO as in the middle-tier API tab. The client credential is the managed identity token, which Entra matches against the federated credential.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', client_id: ID.wiqApp.appId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{Tfic}}', assertion: '{{Ta}}', scope: `${WIQ_SCOPE}`, requested_token_use: 'on_behalf_of' } } },
      { id: 'fw-obo-res', from: 'entra', to: 'search', label: 'Twiq (user, via connector)', title: 'Delegated Work IQ token', det: 'policy', desc: '', tok: ['Twiq'], res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', scope: WIQ_SCOPE, expires_in: 4799, access_token: '{{Twiq}}' } }, checks: [{ name: `Federated credential ${ID.wiqApp.ficId.slice(0, 8)}…: subject = search MI`, ok: true }, { name: 'Admin consent for WorkIQAgent.Ask on the connector app', ok: true }, { name: 'Conditional Access for the user', ok: true }] },
      { id: 'fw-wiq', from: 'search', to: 'workiq', label: 'Ask as Alex (Bearer Twiq)', title: 'Search calls Work IQ for the user', det: 'protocol', desc: 'The request body isn\'t documented, so it\'s left out here.' },
      { id: 'fw-m365', from: 'workiq', to: 'm365', label: 'Ground as Alex', title: 'Microsoft 365 permissions apply', det: 'policy', desc: 'Work IQ applies Microsoft 365 permissions on every request, the same as in the Work IQ tab.', checks: [{ name: 'Falcon status mail thread (Alex is a recipient)', ok: true }, { name: 'Falcon steering minutes (Alex not invited)', ok: false, detail: 'Trimmed' }] },
      { id: 'fw-wiq-res', from: 'workiq', to: 'search', label: 'Passages + citations', title: 'Work IQ answers', det: 'protocol', desc: '' },
      { id: 'fw-res', from: 'search', to: 'webapp', label: '200 references + activity', title: 'Merged result', det: 'protocol', desc: 'A 206 would mean one source failed and another worked. A 502 means all of them failed, for example a broken federated credential.', res: { status: 200, statusText: 'OK', json: { activity: [{ type: 'workIQ', knowledgeSourceName: 'my-workiq-ks', count: 1, elapsedMs: 41137 }], references: [{ type: 'workIQ', id: '0' }, { type: 'searchIndex', id: '1', docKey: 'falcon-plan.docx' }] } } },
      { id: 'fw-show', from: 'webapp', to: 'user', label: 'Status with sources', title: 'User gets one answer from both', det: 'protocol', desc: 'Each source trimmed with its own rules, and every hop ran as Alex.' },
    ],
  });

  /* ---------- Oversharing comparison ---------- */
  FLOWS.push({
    id: 'iq-oversharing', group: 'iq', icon: '🫗', live: false,
    title: 'Oversharing: three setups',
    subtitle: 'A contractor asks about salaries. Pick a setup and watch where the salary file gets stopped, or doesn\'t.',
    actors: ['user', 'foundry', 'llm', 'entra', 'search', 'graph'],
    layout: { user: [100, 220], foundry: [400, 220], llm: [400, 480], entra: [400, 30], search: [740, 330], graph: [740, 110] },
    variants: [
      { id: 'trimmed', label: 'User token + synced ACLs', desc: 'Knowledge source ingests permissions, and the agent passes the user\'s token on every call.' },
      { id: 'no-acl', label: 'Index without permissions', desc: 'Same agent and token, but the knowledge source was created without ingestionPermissionOptions.' },
      { id: 'app-only', label: 'Agent reads with its own rights', desc: 'A home-made RAG agent searches SharePoint through Graph with an app-only token and Sites.Read.All.' },
    ],
    brief: {
      what: 'Oversharing in AI is almost never the model\'s fault. It comes from <b>whose identity reaches the data</b> and <b>whether the data knows its own permissions</b>. Run the three variants. Only the first keeps the salary file away from a contractor. In the other two the answer still looks plausible, and nothing in it tells you something went wrong.',
      prereqs: ['Alex is a contractor in Procurement', 'The salary bands file is on the HR site, readable by the HR group only', 'The agent identity has broad read access, as agents often do'],
      antiPattern: 'Grounding an agent with app-only rights such as Sites.Read.All or Files.Read.All, or with an index that has no permission fields. Every user then gets whatever the agent can read. Use delegated or OBO access, permission-aware knowledge sources, and test with a low-privilege user.',
      verify: 'Simulated only. The same three patterns apply to Fabric IQ: ontology and semantic model sources run OBO as the user, while a Fabric data agent MCP endpoint also accepts a service principal token and then applies that principal\'s rights.',
    },
    tokens: (ctx) => ({
      Tq: { label: 'Tq: user token for Azure AI Search', ...userTok(ctx.t + 1, SEARCH_AUD, 'user_impersonation', ID.webapp.appId) },
      Tmi: miTok(ctx.t + 1, SEARCH_AUD, ID.foundry.miOid, 'Tmi: agent managed identity token for Search'),
      Tapp: { label: 'Tapp: app-only Graph token with Sites.Read.All', ...TK.app(ctx.t + 1, { aud: GRAPH, azp: RAG_APP, oid: uuid(), roles: ['Sites.Read.All'], v1: true, extra: { app_displayname: 'Contoso RAG bot' } }) },
    }),
    steps: (ctx) => {
      const v = ctx.variant || 'trimmed';
      const head = [
        { id: 'os-ask', from: 'user', to: 'foundry', label: '"Salary band for Head of Procurement?"', title: 'A contractor asks about pay', det: 'human', desc: 'Alex shouldn\'t see salary data. The answer depends entirely on the setup, not on the model.' },
        { id: 'os-pick', from: 'llm', to: 'foundry', label: 'tool_call: search', title: 'Model decides to search', det: 'ai', desc: 'Same decision in all three variants.' },
      ];
      if (v === 'app-only') {
        return [...head,
          { id: 'os-cc', from: 'foundry', to: 'entra', label: 'client_credentials (Graph)', title: 'Agent gets an app-only token', det: 'protocol', desc: 'No user anywhere in this request.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: RAG_APP, grant_type: 'client_credentials', scope: `${GRAPH}/.default`, client_assertion: '…[masked]' } } },
          { id: 'os-cc-res', from: 'entra', to: 'foundry', label: 'Tapp (roles = Sites.Read.All)', title: 'App-only token', det: 'policy', desc: 'Entra checks that an admin granted the application permission. It knows nothing about Alex.', tok: ['Tapp'], checks: [{ name: 'Admin consent for Sites.Read.All (application)', ok: true }, { name: 'User context', ok: null, detail: 'None. idtyp = app' }] },
          { id: 'os-graph', from: 'foundry', to: 'graph', label: 'POST /search/query (Bearer Tapp)', title: 'Search all sites as the app', det: 'protocol', desc: '', req: { method: 'POST', url: `${GRAPH}/v1.0/search/query`, headers: { ...HDR.json, ...HDR.bearer('Tapp') }, json: { requests: [{ entityTypes: ['driveItem'], query: { queryString: 'salary band head of procurement' }, region: 'EUR' }] } } },
          { id: 'os-graph-res', from: 'graph', to: 'foundry', label: 'Salary bands 2026.xlsx', title: 'Graph returns what the app can read', det: 'policy', status: 'error', desc: 'Graph trims to the caller. The caller is the app, and the app can read every site.', checks: [{ name: 'HR site readable by the caller', ok: true, detail: 'Caller is the app, not Alex' }], res: { status: 200, statusText: 'OK', json: { value: [{ hitsContainers: [{ hits: [{ resource: { name: 'Salary bands 2026.xlsx', parentReference: { siteId: 'hr' } } }] }] }] } } },
          { id: 'os-leak', from: 'foundry', to: 'user', label: '"The band is 95k to 120k"', title: 'Overshared answer', det: 'ai', status: 'error', desc: 'Alex now knows the salary band. The audit log shows the agent read the file, not Alex.' },
        ];
      }
      const noAcl = v === 'no-acl';
      return [...head,
        { id: 'os-call', from: 'foundry', to: 'search', label: 'retrieve (Tmi + Tq)', title: 'Retrieve with both tokens', det: 'protocol', desc: noAcl ? 'The agent does everything right. The problem was baked in when the knowledge source was created.' : '', req: { method: 'POST', url: KB_RETRIEVE, headers: { ...HDR.json, ...HDR.bearer('Tmi'), 'x-ms-query-source-authorization': '{{Tq}}' }, json: { messages: [{ role: 'user', content: [{ type: 'text', text: 'Salary band for Head of Procurement' }] }] } } },
        { id: 'os-authz', from: 'search', to: 'search', label: noAcl ? 'No permission fields' : 'Build security filter', title: noAcl ? 'Nothing to filter on' : 'Search builds the user\'s filter', det: 'policy', status: noAcl ? 'error' : undefined,
          desc: noAcl ? 'The index has no userIds, groupIds or rbacScope fields, so Search returns results unfiltered whatever the header says. The only fix is to recreate the knowledge source with ingestionPermissionOptions.' : 'Alex\'s groups are Procurement and All staff. The salary file\'s ACL is HR only.',
          checks: noAcl ? [{ name: 'Permission filter fields in index', ok: false, detail: 'ingestionPermissionOptions not set' }, { name: 'Salary bands 2026.xlsx', ok: true, detail: 'Returned to everyone' }] : [{ name: 'Query token user = Alex', ok: true }, { name: 'Salary bands 2026.xlsx: groupIds = HR', ok: false, detail: 'Filtered out' }, { name: 'Procurement role profile.docx: All staff', ok: true }] },
        noAcl
          ? { id: 'os-res', from: 'search', to: 'foundry', label: 'Salary bands 2026.xlsx', title: 'Unfiltered references', det: 'protocol', status: 'error', desc: '', res: { status: 200, statusText: 'OK', json: { references: [{ type: 'searchIndex', docKey: 'salary-bands-2026.xlsx' }, { type: 'searchIndex', docKey: 'procurement-role-profile.docx' }] } } }
          : { id: 'os-res', from: 'search', to: 'foundry', label: 'Role profile only', title: 'Trimmed references', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { references: [{ type: 'searchIndex', docKey: 'procurement-role-profile.docx' }] } } },
        noAcl
          ? { id: 'os-leak', from: 'foundry', to: 'user', label: '"The band is 95k to 120k"', title: 'Overshared answer', det: 'ai', status: 'error', desc: 'The query token was there all along. It had nothing to match against.' }
          : { id: 'os-safe', from: 'foundry', to: 'user', label: '"I can\'t find pay data you can access"', title: 'Safe answer', det: 'ai', desc: 'The model never saw the salary file, so no prompt trick can pull it out.' },
      ];
    },
  });
}
