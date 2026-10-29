'use strict';
/* =====================================================================
   FLOW DEFINITIONS: access, MFA, devices and risk (part 1: step-up)
   ===================================================================== */
const CLAIMS_C1 = '{"access_token":{"acrs":{"essential":true,"value":"c1"}}}';
const PAY_URL = 'https://orders.contoso.com/api/payments/PO-10442/approve';

FLOWS.push({
  id: 'step-up', group: 'access', icon: '⬆️', live: true,
  title: 'Step-up MFA for a sensitive action',
  subtitle: 'The API asks for stronger authentication before it approves a payment, and Entra enforces it.',
  actors: ['user', 'browser', 'agent', 'entra', 'api'],
  layout: { user: [110, 80], browser: [110, 360], agent: [480, 420], entra: [480, 90], api: [860, 300] },
  variants: [
    { id: 'direct', label: 'User in the app', desc: 'The user clicks Approve in the web app. The API challenges, the app steps the user up and retries.' },
    { id: 'agent', label: 'Agent acting for the user', desc: 'An agent tries the same approval on the user\'s behalf. It can\'t do MFA, so the challenge goes back to the human.' },
  ],
  brief: {
    what: 'An <b>authentication context</b> such as <code>c1</code> labels a sensitive action. A Conditional Access policy says what c1 needs, for example phishing-resistant MFA. The API checks the <code>acrs</code> claim before it acts. If c1 is missing, it answers 401 with a <b>claims challenge</b>. The client sends the user back to Entra with those claims, and the retry succeeds with a token that carries <code>acrs: ["c1"]</code>. For agents this is human in the loop that Entra enforces, not a prompt the model could talk its way around.<br><br>Watch for three separate decisions. <b>Entra issues</b> the token after its own policy. <b>The API validates</b> it: signature, issuer, audience, lifetime. Then <b>the API authorizes</b> the action with its own rule, here "payments over 10 000 EUR need c1". A valid token is not permission. The stage chips on each step and the two groups on the Checks tab keep these apart.',
    prereqs: ['Entra ID P1', 'An authentication context, here c1 "Approve payment"', 'A Conditional Access policy that targets c1 and requires MFA or an authentication strength', 'An API that checks <code>acrs</code> and returns the claims challenge', 'A client that can pass <code>claims</code> to /authorize. MSAL does this'],
    antiPattern: 'Checking "did the user do MFA at some point" by reading <code>amr</code> in the API, or building your own second prompt. Both skip Conditional Access, so the policy, the logs and the phishing-resistant requirement never come into play.',
    verify: 'Live mode needs <code>-EnableStepUpPolicy</code> during provisioning. That creates the context and a policy scoped to the demo user only. If the user did MFA recently, Entra may satisfy c1 without a new prompt, and the claim still shows up.',
  },
  tokens: (ctx) => ({
    Tc: { label: 'Tc: user token from the morning sign-in, no acrs', ...TK.user(ctx.t - 3000, { aud: ID.api.appId, scp: 'access_as_user', azp: ID.spa.appId, extra: { amr: ['pwd', 'mfa'] } }) },
    Tc2: { label: 'Tc2: stepped-up token with acrs c1', ...TK.user(ctx.t, { aud: ID.api.appId, scp: 'access_as_user', azp: ID.spa.appId, extra: { acrs: ['c1'], amr: ['mfa'] } }) },
    Tb: { label: 'User token for the agent, aud = blueprint', ...TK.user(ctx.t - 3000, { aud: ID.blueprint.appId, scp: 'access_as_user', azp: ID.spa.appId, extra: { amr: ['pwd', 'mfa'] } }) },
    Tb2: { label: 'Stepped-up user token for the agent, acrs c1', ...TK.user(ctx.t, { aud: ID.blueprint.appId, scp: 'access_as_user', azp: ID.spa.appId, extra: { acrs: ['c1'], amr: ['mfa'] } }) },
    Ta: { label: 'Agent OBO token for the Orders API, no acrs', ...TK.user(ctx.t + 1, { aud: ID.api.appId, scp: 'access_as_user', azp: ID.agent.appId, azpacr: '2', extra: { xms_act_fct: '3 9 11', xms_par_app_azp: ID.blueprint.appId } }) },
    Ta2: { label: 'Agent OBO token with acrs c1', ...TK.user(ctx.t + 2, { aud: ID.api.appId, scp: 'access_as_user', azp: ID.agent.appId, azpacr: '2', extra: { acrs: ['c1'], xms_act_fct: '3 9 11', xms_par_app_azp: ID.blueprint.appId } }) },
  }),
  steps: (ctx) => {
    const challengeHdr = { 'WWW-Authenticate': `Bearer realm="", authorization_uri="${AUTHZ_EP}", error="insufficient_claims", claims="${btoa(CLAIMS_C1)}"` };
    const stepUp = (p, tok, scope) => [
      { id: `${p}-authz`, from: 'browser', to: 'entra', label: 'GET /authorize + claims', title: 'Back to Entra with the claims', det: 'protocol', desc: 'The client adds the <code>claims</code> parameter from the challenge. Everything else is a normal auth code + PKCE request.',
        req: { method: 'GET', url: AUTHZ_EP, query: { client_id: ID.spa.appId, response_type: 'code', redirect_uri: REDIRECT, scope, claims: CLAIMS_C1, code_challenge: '{{challenge}}', code_challenge_method: 'S256', state: '{{state}}' } } },
      { id: `${p}-policy`, from: 'entra', to: 'entra', label: 'CA policy for c1', title: 'Entra applies the c1 policy', det: 'policy',
        desc: 'The claims ask for c1, so Entra evaluates every Conditional Access policy that targets that context. This one requires phishing-resistant MFA, so a password plus push isn\'t enough.',
        checks: [{ name: 'Policy "Approve payment" targets authentication context c1', ok: true }, { name: 'Grant: authentication strength phishing-resistant MFA', ok: true, detail: 'The user has a passkey registered' }, { name: 'Sign-in frequency: every time for c1', ok: true }] },
      { id: `${p}-signin`, from: 'entra', to: 'user', label: 'Passkey prompt', title: 'User proves it\'s really them', det: 'human', desc: 'The user touches the passkey or uses Windows Hello. Entra issues a new code once the policy is satisfied.' },
      { id: `${p}-token-res`, from: 'entra', to: 'browser', label: '200 token with acrs c1', title: 'New token carries acrs', det: 'protocol', desc: 'The client redeems the code as usual. The new access token contains <code>acrs: ["c1"]</code>.', res: { status: 200, statusText: 'OK', json: { token_type: 'Bearer', expires_in: 4799, access_token: `{{${tok}}}` } } },
    ];
    if (ctx.variant !== 'agent') {
      return [
        { id: 'su-start', from: 'user', to: 'browser', label: 'Approve PO-10442', title: 'User clicks Approve', det: 'human', desc: `${ID.user.name} signed in this morning with a password and push MFA. Now they approve a 12 400 EUR payment.` },
        { id: 'su-call-req', from: 'browser', to: 'api', label: 'POST /approve (Bearer Tc)', title: 'App calls the API', det: 'protocol', desc: 'The app sends the token it already has.', req: { method: 'POST', url: PAY_URL, headers: { ...HDR.json, ...HDR.bearer('Tc') }, json: { paymentId: 'PO-10442', amount: 12400 } } },
        { id: 'su-validate', from: 'api', to: 'api', label: 'Validate, then authorize', title: 'API validates the token, then decides on the payment', det: 'resource', desc: 'Two separate questions. Is this token genuine and meant for me? Yes. Is this caller allowed to approve 12 400 EUR? The API\'s own rule says payments over 10 000 EUR need c1, and the token doesn\'t carry it. So the answer is no, even though the token is valid.', tok: ['Tc'],
          checks: [{ name: 'Signature, iss, aud, exp', ok: true, kind: 'token' }, { name: 'scp contains access_as_user', ok: true, kind: 'access' }, { name: 'acrs contains c1 (payments over 10 000 EUR)', ok: false, detail: 'no acrs claim', kind: 'access' }] },
        { id: 'su-challenge', from: 'api', to: 'browser', label: '401 insufficient_claims', title: 'API sends a claims challenge', det: 'policy', status: 'pending', desc: 'The <code>claims</code> value is base64 JSON asking for <code>acrs = c1</code>. The API doesn\'t decide what c1 needs. The Conditional Access policy does.',
          res: { status: 401, statusText: 'Unauthorized', headers: challengeHdr, json: { error: 'insufficient_claims', claims: CLAIMS_C1 } }, kv: { claims: CLAIMS_C1 } },
        ...stepUp('su2', 'Tc2', SCOPE.api),
        { id: 'su-call2-req', from: 'browser', to: 'api', label: 'POST /approve (Bearer Tc2)', title: 'App retries', det: 'protocol', desc: 'Same request, better token.', req: { method: 'POST', url: PAY_URL, headers: { ...HDR.json, ...HDR.bearer('Tc2') }, json: { paymentId: 'PO-10442', amount: 12400 } } },
        { id: 'su-approve', from: 'api', to: 'api', label: 'acrs c1 present', title: 'API approves', det: 'resource', desc: 'The token validates as before, and now it carries c1, so the API\'s own rule lets the payment through.', tok: ['Tc2'],
          checks: [{ name: 'Signature, iss, aud, exp', ok: true, kind: 'token' }, { name: 'acrs contains c1 (payments over 10 000 EUR)', ok: true, kind: 'access' }] },
        { id: 'su-approve-res', from: 'api', to: 'browser', label: '200 approved', title: 'Payment approved', det: 'protocol', desc: 'The audit log records who approved and that c1 was satisfied.', res: { status: 200, statusText: 'OK', json: { approved: true, paymentId: 'PO-10442', amount: 12400, acrs: ['c1'] } } },
      ];
    }
    return [
      { id: 'sa-ask', from: 'user', to: 'browser', label: '"Approve PO-10442"', title: 'User asks the agent', det: 'human', desc: 'The user asks the agent in chat to approve the payment.' },
      { id: 'sa-call', from: 'browser', to: 'agent', label: 'POST /chat (Bearer)', title: 'Chat app calls the agent', det: 'protocol', desc: 'The user token has the blueprint as audience, as in the Agent OBO tab.', req: { method: 'POST', url: 'https://assistant.contoso.com/api/chat', headers: HDR.bearer('Tb'), json: { prompt: 'Approve PO-10442' } } },
      { id: 'sa-obo', from: 'agent', to: 'entra', label: 'Agent OBO for Orders API', title: 'Agent gets a token for the API', det: 'protocol', desc: 'T1 then OBO, condensed here. The Agent OBO tab shows the full exchange.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.agent.appId, client_assertion: '<T1>', grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: '{{Tb}}', requested_token_use: 'on_behalf_of', scope: `api://${ID.api.appId}/.default` } } },
      { id: 'sa-obo-res', from: 'entra', to: 'agent', label: 'Ta, no acrs', title: 'Agent holds a token without c1', det: 'protocol', desc: 'A perfectly good token for normal calls.', res: { status: 200, statusText: 'OK', json: { access_token: '{{Ta}}' } } },
      { id: 'sa-api', from: 'agent', to: 'api', label: 'POST /approve (Bearer Ta)', title: 'Agent calls the API', det: 'protocol', desc: 'The model decided to approve. That decision alone gets it nowhere.', req: { method: 'POST', url: PAY_URL, headers: HDR.bearer('Ta'), json: { paymentId: 'PO-10442', amount: 12400 } } },
      { id: 'sa-validate', from: 'api', to: 'api', label: 'Validate, then authorize', title: 'API validates the token, then decides on the action', det: 'resource', tok: ['Ta'],
        desc: 'Entra already issued this token, and it is valid. That only answers "is this genuine and meant for me". Whether an agent may approve a 12 400 EUR payment is the API\'s own decision, made here at the moment of the action. Its rule needs c1, so the answer is no.',
        why: 'Token issuance, token validation and authorization are three different decisions by two different parties. A model that has decided to act, and holds a valid token, still has to pass the resource\'s own rule.',
        checks: [{ name: 'Signature, iss, aud, exp', ok: true, kind: 'token' }, { name: 'scp contains access_as_user', ok: true, kind: 'access' }, { name: 'Caller is an agent acting for a user (xms_act_fct)', ok: true, detail: 'Logged so the audit names both the user and the agent', kind: 'access' }, { name: 'acrs contains c1 (payments over 10 000 EUR)', ok: false, detail: 'no acrs claim', kind: 'access' }] },
      { id: 'sa-challenge', from: 'api', to: 'agent', label: '401 insufficient_claims', title: 'Same challenge, aimed at the agent', det: 'resource', status: 'pending', desc: 'The rule is the same whoever calls. No c1, no approval. The API returns the claims challenge so the caller knows how to get past it.', res: { status: 401, statusText: 'Unauthorized', headers: challengeHdr } },
      { id: 'sa-cannot', from: 'agent', to: 'agent', label: 'Can\'t do MFA', title: 'The agent can\'t satisfy it', det: 'protocol', desc: 'An agent has no passkey and no face. Retrying OBO with the claims only gets <code>interaction_required</code>, because the user\'s own token lacks c1.' },
      { id: 'sa-back', from: 'agent', to: 'browser', label: 'Needs step-up + claims', title: 'Agent hands the challenge to the human', det: 'protocol', desc: 'The agent returns the claims to the chat client and asks the user to confirm.', res: { status: 401, statusText: 'Unauthorized', json: { error: 'step_up_required', claims: CLAIMS_C1, message: 'Approving a payment needs you to confirm with your passkey.' } } },
      ...stepUp('sa2', 'Tb2', SCOPE.blueprint),
      { id: 'sa-retry', from: 'browser', to: 'agent', label: 'Retry with Tb2', title: 'Chat client retries', det: 'protocol', desc: 'The user token now carries c1.', req: { method: 'POST', url: 'https://assistant.contoso.com/api/chat', headers: HDR.bearer('Tb2') } },
      { id: 'sa-obo2', from: 'agent', to: 'entra', label: 'OBO again + claims', title: 'Agent exchanges the stepped-up token', det: 'protocol', desc: 'The agent passes the claims in its OBO request. The user\'s token already satisfies c1, so the new API token carries it too.', req: { method: 'POST', url: TOKEN_EP, headers: HDR.form, form: { client_id: ID.agent.appId, client_assertion: '<T1>', grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: '{{Tb2}}', requested_token_use: 'on_behalf_of', scope: `api://${ID.api.appId}/.default`, claims: CLAIMS_C1 } } },
      { id: 'sa-obo2-res', from: 'entra', to: 'agent', label: 'Ta2 with acrs c1', title: 'Agent token now carries c1', det: 'policy', desc: 'Entra copies the satisfied context into the downstream token.', res: { status: 200, statusText: 'OK', json: { access_token: '{{Ta2}}' } } },
      { id: 'sa-api2', from: 'agent', to: 'api', label: 'POST /approve (Bearer Ta2)', title: 'Agent calls again', det: 'protocol', desc: '', req: { method: 'POST', url: PAY_URL, headers: HDR.bearer('Ta2') } },
      { id: 'sa-approve', from: 'api', to: 'api', label: 'acrs c1 present', title: 'API validates and authorizes again', det: 'resource', tok: ['Ta2'], desc: 'Same two questions. The token is genuine, and now it proves the user stepped up for c1, so the API\'s rule allows the agent to approve.',
        checks: [{ name: 'Signature, iss, aud, exp', ok: true, kind: 'token' }, { name: 'Caller is an agent acting for a user (xms_act_fct)', ok: true, kind: 'access' }, { name: 'acrs contains c1 (payments over 10 000 EUR)', ok: true, kind: 'access' }] },
      { id: 'sa-ok', from: 'api', to: 'agent', label: '200 approved', title: 'Approved, with a human in the loop', det: 'protocol', desc: 'The audit trail names the user, the agent and the c1 step-up.', res: { status: 200, statusText: 'OK', json: { approved: true, approvedBy: ID.user.upn, via: ID.agent.appId, acrs: ['c1'] } } },
    ];
  },
});
