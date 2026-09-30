'use strict';
/* =====================================================================
   FLOW DEFINITIONS: Microsoft Entra Agent ID
   Verified against Learn: agent-on-behalf-of-oauth-flow, agent-user-oauth-flow, agent-token-claims.
   ===================================================================== */
const AGENT_FACETS = { xms_act_fct: '3 9 11', xms_idrel: '7', xms_tnt_fct: '3 9' };

function agentParentSteps(p, credNote) {
  return [
    { id: `${p}-mi-req`, from: 'agent', to: 'imds', label: 'MI token for api://AzureADTokenExchange', title: 'Get the blueprint credential from a managed identity', det: 'protocol',
      desc: 'In production the blueprint\'s credential is a <b>managed identity acting as a federated credential</b>. The host asks its managed identity for a token with audience <code>api://AzureADTokenExchange</code>.' + (credNote ? ` <i>${credNote}</i>` : ''),
      req: { method: 'GET', url: 'http://169.254.169.254/metadata/identity/oauth2/token', query: { 'api-version': '2018-02-01', resource: 'api://AzureADTokenExchange' }, headers: { Metadata: 'true' } } },
    { id: `${p}-mi-res`, from: 'imds', to: 'agent', label: 'TUAMI', title: 'Managed identity token (TUAMI)', det: 'protocol', desc: 'This token is the blueprint\'s credential. There\'s no secret stored anywhere.', res: { status: 200, statusText: 'OK', json: { access_token: '{{TUAMI}}', token_type: 'Bearer', resource: 'api://AzureADTokenExchange' } } },
    { id: `${p}-parent-req`, from: 'agent', to: 'entra', label: 'Step 1: client_credentials + fmi_path', title: 'Step 1: the blueprint asks for an exchange token (T1)', det: 'protocol',
      desc: 'The <b>blueprint</b> signs in with its credential and names the agent identity it wants to act as. It does that with <code>fmi_path</code>, set to the agent identity\'s appId. The scope is always <code>api://AzureADTokenExchange/.default</code>.',
      why: 'Agent identities can\'t hold credentials. Only the blueprint can, and it only gets T1 for agent identities it created.',
      req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.blueprint.appId, scope: 'api://AzureADTokenExchange/.default', fmi_path: ID.agent.appId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{TUAMI}}', grant_type: 'client_credentials' } } },
    { id: `${p}-parent-res`, from: 'entra', to: 'agent', label: 'T1 (exchange token)', title: 'T1 issued', det: 'policy', desc: 'T1 can\'t call any API. Its one job is to be the client assertion for this particular agent identity.', res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', expires_in: 3599, access_token: '{{T1}}' } },
      checks: [{ name: 'Blueprint credential valid: federated credential matches the managed identity\'s issuer and subject', ok: true }, { name: 'fmi_path agent identity is a child of this blueprint', ok: true }, { name: 'Agent identity enabled. No admin or sponsor has switched it off', ok: true }] },
  ];
}
const T1_TOKEN = (ctx) => ({ label: 'T1: exchange token (blueprint → agent identity)', header: TK.hdr(), payload: { aud: 'api://AzureADTokenExchange', iss: ISS_V2, ...TK.times(ctx.t, 3599), azp: ID.blueprint.appId, azpacr: '2', idtyp: 'app', oid: ID.blueprint.spOid, sub: ID.blueprint.spOid, tid: ID.tid, ver: '2.0' } });
const TUAMI_TOKEN = (ctx) => ({ label: 'TUAMI: managed identity token (the blueprint credential)', ...TK.app(ctx.t, { aud: 'fb60f99c-7a34-4190-8149-302f77469936', azp: ID.mi.clientId, oid: ID.mi.oid, roles: undefined, extra: { azpacr: '2', xms_mirid: '/subscriptions/1c2d…/resourcegroups/rg-agents/providers/Microsoft.ManagedIdentity/userAssignedIdentities/uami-assistant' } }) });

/* ---------- 8. Agent autonomous ---------- */
function aaVariant(ctx, steps) {
  const i = steps.findIndex((s) => s.id === 'aa-agent-req');
  const blocked = ctx.variant === 'blocked';
  const ca = { id: 'aa-ca', from: 'entra', to: 'entra', label: 'Conditional Access for agents', title: 'Entra evaluates policies for the agent identity', det: 'policy',
    desc: 'Conditional Access can target agent identities, and ID Protection gives them a risk level. This is still in preview, so check the current scope before promising it to a customer.',
    checks: blocked
      ? [{ name: 'Agent identity risk', ok: false, detail: 'High. Unusual volume of directory reads from a new location' }, { name: 'Policy "Block high-risk agents" applies', ok: false }]
      : [{ name: 'Agent identity risk', ok: true, detail: 'None' }, { name: 'Agent policies satisfied', ok: true }] };
  if (!blocked) return [...steps.slice(0, i + 1), ca, ...steps.slice(i + 1)];
  return [...steps.slice(0, i + 1), ca,
    { id: 'aa-agent-res', from: 'entra', to: 'agent', label: '400 blocked', title: 'No token for a risky agent', det: 'policy', status: 'error', desc: 'The agent gets no token, so it can\'t touch Graph. Its sponsor gets to investigate before an admin re-enables it or dismisses the risk.',
      res: { status: 400, statusText: 'Bad Request', json: { error: 'invalid_grant', error_description: 'AADSTS53003: Access has been blocked by Conditional Access policies.' } } },
  ];
}
FLOWS.push({
  id: 'agent-autonomous', group: 'agent', icon: '🤖', live: true,
  title: 'Agent ID: autonomous (app-only)',
  subtitle: 'The agent acts as itself, with its own identity and permissions and no user anywhere.',
  actors: ['llm', 'agent', 'imds', 'entra', 'graph'],
  layout: { llm: [130, 90], agent: [130, 330], imds: [470, 400], entra: [520, 110], graph: [870, 330] },
  variants: [
    { id: 'allowed', label: 'Healthy agent', desc: 'Conditional Access for agents evaluates the agent identity and lets it through.' },
    { id: 'blocked', label: 'High-risk agent', desc: 'ID Protection has flagged this agent identity as high risk, and a Conditional Access policy for agents blocks it.' },
  ],
  brief: {
    what: 'Agents that run on their own, for triage, monitoring or scheduled reviews, use a <b>two-step exchange</b>. First the blueprint gets T1 for one specific agent identity. Then that agent identity uses T1 as its credential and gets a resource token. The token\'s subject is the agent identity itself. So every agent instance shows up separately in the logs, and you can switch one off without touching the others.',
    prereqs: ['An agent identity blueprint and its BlueprintPrincipal', 'An agent identity created from the blueprint, with a sponsor', 'A credential on the <b>blueprint</b>. A managed identity federated credential in production, a certificate, or a secret in dev only', 'An application permission such as User.Read.All, granted to the <b>agent identity</b>'],
    antiPattern: 'One shared, all-powerful service principal for every agent, or permissions granted to the blueprint instead of each agent identity. Either way you can no longer tell agents apart in the logs, every agent gets every permission, and you can\'t turn off just one of them.',
    verify: 'Live mode uses a client secret on the blueprint, because a laptop has no managed identity. You\'ll only see the managed identity steps in Simulated mode.',
  },
  tokens: (ctx) => ({
    TUAMI: TUAMI_TOKEN(ctx), T1: T1_TOKEN(ctx),
    AT: { label: 'Agent token (aud = Graph, subject = agent identity)', ...TK.app(ctx.t + 1, { aud: GRAPH, azp: ID.agent.appId, oid: ID.agent.spOid, roles: ['User.Read.All'], v1: true, extra: { appidacr: '2', ...AGENT_FACETS, xms_sub_fct: '9 3 11', xms_par_app_azp: ID.blueprint.appId } }) },
  }),
  steps: (ctx) => aaVariant(ctx, [
    { id: 'aa-trigger', from: 'agent', to: 'agent', label: 'Scheduled: weekly access review', title: 'Agent wakes up', det: 'protocol', desc: 'A schedule, a queue message or a webhook starts the agent. No user is present.' },
    { id: 'aa-plan-req', from: 'agent', to: 'llm', label: 'Goal + tool schemas', title: 'Host asks the model what to do', det: 'protocol', desc: 'The host sends the goal and the list of tools. <b>The model never gets a credential.</b>', req: { method: 'POST', url: 'https://contoso-aoai.openai.azure.com/openai/v1/responses', headers: HDR.json, json: { model: 'gpt-4.1', input: 'Run the weekly access review for new guest accounts.', tools: [{ type: 'function', name: 'directory_list_users', parameters: { type: 'object', properties: { top: { type: 'integer' } } } }] } } },
    { id: 'aa-plan-res', from: 'llm', to: 'agent', label: 'tool_call: directory_list_users', title: 'The model picks a tool', det: 'ai', desc: 'The model picks <b>the tool and its arguments</b>. That\'s the only non-deterministic step in the whole flow. Entra and the resource decide whether the call is <i>allowed</i>.', res: { status: 200, statusText: 'OK', json: { output: [{ type: 'function_call', name: 'directory_list_users', arguments: '{"top":1}' }] } } },
    ...agentParentSteps('aa'),
    { id: 'aa-agent-req', from: 'agent', to: 'entra', label: 'Step 2: client_assertion=T1', title: 'Step 2: the agent identity asks for a resource token', det: 'protocol', desc: 'Now <code>client_id</code> is the <b>agent identity</b> and its credential is T1. The scope is the resource\'s <code>/.default</code>.',
      why: 'Step 1 has to be <code>client_credentials</code> with <code>fmi_path</code>. Try the RFC 8693 token-exchange grant instead and Entra answers with AADSTS82001.',
      req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.agent.appId, scope: 'https://graph.microsoft.com/.default', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{T1}}', grant_type: 'client_credentials' } } },
    { id: 'aa-agent-res', from: 'entra', to: 'agent', label: 'Agent token (sub = agent)', title: 'Agent token issued', det: 'policy', desc: 'The token belongs to the agent identity. <code>xms_act_fct</code> contains <b>11</b>, which means AgentIdentity. <code>xms_par_app_azp</code> names the blueprint, so audits can trace the agent back to it.', res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', expires_in: 3599, access_token: '{{AT}}' } },
      checks: [{ name: 'T1 was issued to the parent blueprint', ok: true }, { name: 'App roles assigned to this exact agent identity', ok: true, detail: 'User.Read.All' }, { name: 'Conditional Access for agents', ok: true }] },
    { id: 'aa-graph-req', from: 'agent', to: 'graph', label: 'GET /users', title: 'Agent calls Graph', det: 'protocol', desc: '', req: { method: 'GET', url: `${GRAPH}/v1.0/users?$top=1&$select=id,displayName`, headers: HDR.bearer('AT') } },
    { id: 'aa-graph-res', from: 'graph', to: 'agent', label: '200 users', title: 'Graph returns data', det: 'protocol', desc: 'Sign-in and audit logs record both the agent identity and its blueprint.', res: { status: 200, statusText: 'OK', json: { value: [{ id: ID.user.oid, displayName: ID.user.name }] } } },
    { id: 'aa-result', from: 'agent', to: 'llm', label: 'Tool result → summarise', title: 'Result back to the model', det: 'ai', desc: 'The model writes up the findings. Treat tool output as <i>untrusted input</i>, because it can carry a prompt injection. That\'s the argument for giving the agent the smallest set of permissions that still works.' },
  ]),
});

/* ---------- 9. Agent on-behalf-of ---------- */
FLOWS.push({
  id: 'agent-obo', group: 'agent', icon: '🧑‍💼', live: true,
  title: 'Agent ID: on-behalf-of a user',
  subtitle: 'A user chats with an agent, and the agent calls Graph as that user. The logs still name the agent.',
  actors: ['user', 'browser', 'agent', 'llm', 'entra', 'graph'],
  layout: { user: [110, 80], entra: [600, 80], browser: [110, 330], agent: [520, 330], llm: [900, 200], graph: [900, 430], imds: [520, 480] },
  brief: {
    what: 'Here an interactive agent works <b>for the signed-in user</b>. The user\'s token is addressed to the <b>blueprint</b>, because the blueprint is the API the client calls. The agent gets T1 in step 1, then runs an OBO exchange with the agent identity as the client. The resulting token has the user as subject, with <code>idtyp=user</code>, and the agent identity as the actor in <code>azp</code>. The agent can do only what the user can do and what the agent was granted, whichever is less.',
    prereqs: [`The blueprint exposes the API scope <code>${esc(SCOPE.blueprint)}</code>`, 'The client app has consent for that scope', 'Delegated permissions for the agent identity, either as admin-consented inheritable permissions on the blueprint or as oauth2PermissionGrants. Interactive consent fails for agent identities with AADSTS82014', 'A credential on the blueprint. Use a managed identity federated credential in production'],
    antiPattern: 'Getting the user token for <b>Graph</b> and handing it straight to the agent. That\'s token passthrough. The OBO step fails with AADSTS50013, and even if it didn\'t, the agent would run with all of the client\'s rights and nothing in the logs would name the agent.',
  },
  tokens: (ctx) => ({
    Tc: { label: 'Tc: user token for the blueprint (aud = blueprint)', ...TK.user(ctx.t, { aud: ID.blueprint.appId, scp: 'access_as_user', azp: ID.spa.appId }) },
    IDT: { label: 'ID token', ...TK.idToken(ctx.t, ID.spa.appId, ctx.vars.nonce) },
    TUAMI: TUAMI_TOKEN(ctx), T1: T1_TOKEN(ctx),
    AT: { label: 'Delegated agent token (subject = user, actor = agent)', ...TK.graphUser(ctx.t + 2, { appid: ID.agent.appId, scp: 'User.Read', appName: ID.agent.name, appidacr: '2', extra: { ...AGENT_FACETS, xms_sub_fct: '1', xms_par_app_azp: ID.blueprint.appId } }) },
  }),
  steps: () => [
    { id: 'ao-ask', from: 'user', to: 'browser', label: '"What\'s my job title?"', title: 'User asks the agent', det: 'human', desc: 'The user types into whatever chat app fronts the agent. That could be Teams, Copilot or a web client.' },
    ...pkceSignInSteps('ao', { scope: `openid profile offline_access ${SCOPE.blueprint}`, tokName: 'Tc', audName: 'Tc (aud = blueprint)', short: true }),
    { id: 'ao-call-req', from: 'browser', to: 'agent', label: 'POST /chat (Bearer Tc)', title: 'Client calls the agent', det: 'protocol', desc: 'The blueprint\'s app ID URI protects the agent\'s endpoint.', req: { method: 'POST', url: 'https://assistant.contoso.com/api/chat', headers: { ...HDR.json, ...HDR.bearer('Tc') }, json: { prompt: 'What\'s my job title?' } } },
    { id: 'ao-validate', from: 'agent', to: 'agent', label: 'Validate Tc', title: 'Agent validates the user token', det: 'protocol', desc: 'The usual resource-server checks. The audience has to be the blueprint.', tok: ['Tc'], checks: [{ name: 'Signature (JWKS)', ok: true }, { name: `aud = ${ID.blueprint.appId} (blueprint)`, ok: true }, { name: 'scp contains access_as_user', ok: true }, { name: 'iss/tid/exp', ok: true }] },
    { id: 'ao-plan-req', from: 'agent', to: 'llm', label: 'Prompt + tools', title: 'Agent consults the model', det: 'protocol', desc: 'The prompt and the tool list go to the model. No tokens go with them.' },
    { id: 'ao-plan-res', from: 'llm', to: 'agent', label: 'tool_call: get_my_profile', title: 'Model chooses a tool', det: 'ai', desc: 'The model decides it needs the user\'s profile.' },
    ...agentParentSteps('ao'),
    { id: 'ao-obo-req', from: 'agent', to: 'entra', label: 'OBO: assertion=Tc, client_assertion=T1', title: 'Agent identity performs the OBO exchange', det: 'protocol', desc: 'The client is the <b>agent identity</b>, with T1 as its credential. The user token Tc goes in as the <code>assertion</code>.',
      why: 'The audience of Tc has to be the blueprint that owns this agent identity. Anything else gets AADSTS50013.',
      req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.agent.appId, scope: 'https://graph.microsoft.com/.default', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{T1}}', grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: '{{Tc}}', requested_token_use: 'on_behalf_of' } } },
    { id: 'ao-obo-res', from: 'entra', to: 'agent', label: 'Delegated agent token', title: 'Token: user as subject, agent as actor', det: 'policy', desc: 'The claims to point at are <code>idtyp=user</code>, <code>oid</code> holding the user, <code>appid</code> holding the agent identity, <code>xms_par_app_azp</code> holding the blueprint and <code>scp</code> holding the delegated grant.',
      res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', scope: 'User.Read', expires_in: 4212, access_token: '{{AT}}' } },
      checks: [{ name: 'Tc aud = blueprint of this agent identity', ok: true }, { name: 'Delegated grant for the agent identity, inherited from the blueprint', ok: true, detail: 'User.Read' }, { name: 'Conditional Access for the user and for agents', ok: true }] },
    { id: 'ao-graph-req', from: 'agent', to: 'graph', label: 'GET /me', title: 'Agent calls Graph as the user', det: 'protocol', desc: '', req: { method: 'GET', url: `${GRAPH}/v1.0/me?$select=displayName,jobTitle`, headers: HDR.bearer('AT') } },
    { id: 'ao-graph-res', from: 'graph', to: 'agent', label: '200 profile', title: 'Profile returned', det: 'protocol', desc: 'The audit log records user Alex acting through agent Contoso Assistant #1, which belongs to the Contoso Assistant blueprint.', res: { status: 200, statusText: 'OK', json: { displayName: ID.user.name, jobTitle: 'Procurement Lead' } } },
    { id: 'ao-result', from: 'agent', to: 'llm', label: 'Tool result', title: 'Model writes the answer', det: 'ai', desc: '' },
    { id: 'ao-call-res', from: 'agent', to: 'browser', label: '200 answer', title: 'Answer to the user', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { answer: 'Your job title is Procurement Lead.' } } },
  ],
});

/* ---------- 10. Agent's user account ---------- */
FLOWS.push({
  id: 'agent-user', group: 'agent', icon: '📬', live: false,
  title: 'Agent ID: agent\'s user account',
  subtitle: 'The agent signs in as its own user account, the way a digital worker with a mailbox would.',
  actors: ['agent', 'imds', 'entra', 'graph'],
  layout: { agent: [140, 300], imds: [140, 80], entra: [540, 150], graph: [870, 300] },
  brief: {
    what: 'Some systems only work with a <b>user object</b>. A mailbox needs one, and so do Teams chats and group or site membership. An <b>agent\'s user account</b> belongs to exactly one agent identity. The credentials chain from the blueprint to the agent identity with T1, then to T2, then through the <code>user_fic</code> grant to the agent user. What comes out is a user token with <code>idtyp=user</code>, where <code>xms_sub_fct</code> contains <b>13</b>, meaning AgentIDUser.',
    prereqs: ['A blueprint and agent identity, set up as for the autonomous flow', 'An agent\'s user account linked to exactly one agent identity', 'Licences for the workloads it uses, such as an Exchange mailbox', 'Delegated permissions granted to the agent identity'],
    antiPattern: 'Making an ordinary user with a password and calling it the bot account. You can\'t govern it as an agent, it needs a password or an MFA exemption, and in the logs it looks exactly like a person.',
    verify: 'The parameters <code>grant_type=user_fic</code>, <code>user_federated_identity_credential</code> and <code>username</code> come from the Learn page "Agent\'s user account impersonation protocol". Agent ID keeps changing, so reread it before showing a customer.',
  },
  tokens: (ctx) => ({
    TUAMI: TUAMI_TOKEN(ctx), T1: T1_TOKEN(ctx),
    T2: { label: 'T2: agent identity exchange token', header: TK.hdr(), payload: { aud: 'api://AzureADTokenExchange', iss: ISS_V2, ...TK.times(ctx.t, 3599), azp: ID.agent.appId, azpacr: '2', idtyp: 'app', oid: ID.agent.spOid, sub: ID.agent.spOid, tid: ID.tid, ver: '2.0' } },
    AT: { label: 'Agent user token (subject = agent user)', header: TK.hdr({ nonce: randStr(43) }), payload: { aud: GRAPH, iss: `https://sts.windows.net/${ID.tid}/`, ...TK.times(ctx.t + 2), appid: ID.agent.appId, appidacr: '2', idtyp: 'user', name: ID.agentUser.name, oid: ID.agentUser.oid, scp: 'Mail.Send Mail.ReadWrite', sub: randStr(43), tid: ID.tid, upn: ID.agentUser.upn, ver: '1.0', ...AGENT_FACETS, xms_sub_fct: '13', xms_par_app_azp: ID.blueprint.appId } },
  }),
  steps: () => [
    { id: 'au-trigger', from: 'agent', to: 'agent', label: 'New request in the agent\'s mailbox', title: 'Agent needs to act as its own user', det: 'protocol', desc: 'Say it needs to reply from its own mailbox.' },
    ...agentParentSteps('au'),
    { id: 'au-t2-req', from: 'agent', to: 'entra', label: 'Step 2: T2 for the agent identity', title: 'Agent identity gets T2', det: 'protocol', desc: 'The agent identity uses T1 as its credential and gets a second exchange token, T2, for itself.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.agent.appId, scope: 'api://AzureADTokenExchange/.default', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{T1}}', grant_type: 'client_credentials' } } },
    { id: 'au-t2-res', from: 'entra', to: 'agent', label: 'T2', title: 'T2 issued', det: 'protocol', desc: 'Entra confirms that T1 came from the blueprint that owns this agent identity.', res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', expires_in: 3599, access_token: '{{T2}}' } } },
    { id: 'au-userfic-req', from: 'agent', to: 'entra', label: 'Step 3: grant_type=user_fic', title: 'Exchange for an agent user token', det: 'protocol', desc: 'T1 goes in as the client assertion and T2 as the user federated credential. <code>username</code> names the agent\'s user account.',
      req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.agent.appId, scope: 'https://graph.microsoft.com/.default', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: '{{T1}}', user_federated_identity_credential: '{{T2}}', username: ID.agentUser.upn, grant_type: 'user_fic', requested_token_use: 'on_behalf_of' } } },
    { id: 'au-policy', from: 'entra', to: 'entra', label: 'Validate chain', title: 'Entra validates the credential chain', det: 'policy', desc: 'Both phases have to use the same client ID. That rule stops one agent from escalating into another agent\'s user.', checks: [{ name: 'T2 aud/subject = this agent identity', ok: true }, { name: 'Agent user is bound to exactly this agent identity', ok: true }, { name: 'Delegated grants for the agent identity', ok: true, detail: 'Mail.Send Mail.ReadWrite' }, { name: 'Conditional Access for agent users', ok: true }] },
    { id: 'au-userfic-res', from: 'entra', to: 'agent', label: 'Agent user token', title: 'User token for the agent\'s account', det: 'protocol', desc: '<code>xms_sub_fct</code> = 13 marks the subject as an agent\'s user account and not a human. <code>idtyp=user</code> on its own can\'t tell the two apart.', res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', expires_in: 4200, access_token: '{{AT}}' } } },
    { id: 'au-graph-req', from: 'agent', to: 'graph', label: 'POST /me/sendMail', title: 'Send mail as the agent\'s user', det: 'protocol', desc: '', req: { method: 'POST', url: `${GRAPH}/v1.0/me/sendMail`, headers: { ...HDR.json, ...HDR.bearer('AT') }, json: { message: { subject: 'Your PO-10442 is approved', toRecipients: [{ emailAddress: { address: ID.user.upn } }] } } } },
    { id: 'au-graph-res', from: 'graph', to: 'agent', label: '202 Accepted', title: 'Mail sent', det: 'protocol', desc: 'The mail arrives from the agent\'s own mailbox.', res: { status: 202, statusText: 'Accepted' } },
  ],
});
