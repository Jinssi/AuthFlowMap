'use strict';
/* =====================================================================
   FLOW DEFINITIONS: access, MFA, devices and risk (part 4: ID Protection)
   ===================================================================== */
FLOWS.push({
  id: 'id-protection', group: 'access', icon: '📈', live: true,
  title: 'Identity Protection and risk',
  subtitle: 'Entra scores the sign-in and the account for risk, and Conditional Access makes the user fix it.',
  actors: ['user', 'browser', 'entra', 'risk', 'graph'],
  layout: { user: [110, 80], browser: [110, 360], entra: [480, 220], risk: [860, 80], graph: [860, 380] },
  variants: [
    { id: 'signin', label: 'Risky sign-in', desc: 'A sign-in from an anonymising VPN in a new country gets medium risk. MFA clears it.' },
    { id: 'user', label: 'Leaked credentials', desc: 'The user\'s password turns up in a breach dump. The account goes high risk until the password changes.' },
  ],
  brief: {
    what: '<b>Sign-in risk</b> is the chance that this particular sign-in isn\'t the real user: an anonymous IP, impossible travel, an unfamiliar location or a token anomaly. <b>User risk</b> is the chance that the account itself is compromised, for example because its credentials leaked. Conditional Access turns risk into action. Medium sign-in risk asks for MFA, high user risk forces a secure password change, and a successful remediation closes the risk without a helpdesk ticket. Agent identities get risk signals too, and Conditional Access for agents can block a risky one.',
    prereqs: ['Entra ID P2', 'Risk-based Conditional Access policies for sign-in risk and user risk', 'Users registered for MFA and self-service password reset, so they can fix risk themselves'],
    antiPattern: 'Turning on risk detection and only sending alerts. Without risk-based policies the attacker keeps the session while someone reads the email.',
    verify: 'Live mode reads your tenant\'s latest risk detections and risky users through Graph with the daemon app. It needs P2 and the IdentityRiskEvent.Read.All and IdentityRiskyUser.Read.All permissions. User names are shortened on screen.',
  },
  tokens: (ctx) => ({ AT: { label: 'Access token after remediation', ...TK.graphUser(ctx.t, { appid: ID.spa.appId, scp: 'User.Read', appName: ID.spa.name, appidacr: '0', extra: { amr: ['pwd', 'mfa'] } }) } }),
  steps: (ctx) => {
    const common = [
      { id: 'ip-authz', from: 'browser', to: 'entra', label: 'Sign-in', title: 'Sign-in reaches Entra', det: 'protocol', desc: 'An ordinary auth code sign-in. Risk scoring happens inside Entra while it processes it.' },
    ];
    if (ctx.variant === 'user') {
      return [
        { id: 'ip-leak', from: 'risk', to: 'risk', label: 'Leaked credentials found', title: 'Password found in a breach dump', det: 'policy', desc: 'Microsoft finds the user\'s username and password pair in a dump and matches it against the password hash synced from Active Directory or stored in Entra.', checks: [{ name: 'Detection: leaked credentials', ok: false, detail: 'User risk raised to high' }] },
        { id: 'ip-signin', from: 'user', to: 'browser', label: 'Signs in on Monday', title: 'User signs in as usual', det: 'human', desc: 'The user has no idea anything happened.' },
        ...common,
        { id: 'ip-score', from: 'entra', to: 'risk', label: 'User risk?', title: 'Entra checks the account\'s risk', det: 'policy', desc: '' },
        { id: 'ip-score-res', from: 'risk', to: 'entra', label: 'User risk: high', title: 'High user risk', det: 'policy', desc: '', kv: { userRiskLevel: 'high', riskEventType: 'leakedCredentials' } },
        { id: 'ip-policy', from: 'entra', to: 'entra', label: 'Require secure password change', title: 'Risk policy applies', det: 'policy', desc: 'The user-risk policy requires MFA and then a password change before any token is issued.', checks: [{ name: 'Policy: high user risk requires password change', ok: true }, { name: 'User registered for MFA and SSPR', ok: true }] },
        { id: 'ip-mfa', from: 'entra', to: 'user', label: 'MFA, then new password', title: 'User proves it\'s them and changes the password', det: 'human', desc: 'The MFA comes first, so an attacker holding only the leaked password can\'t do this step.' },
        { id: 'ip-remediate', from: 'entra', to: 'risk', label: 'Risk remediated', title: 'Risk closes itself', det: 'policy', desc: 'A secure password change remediates user risk. No helpdesk ticket.', checks: [{ name: 'User risk state', ok: true, detail: 'remediated' }] },
        { id: 'ip-token', from: 'entra', to: 'browser', label: 'Tokens', title: 'Sign-in completes', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { access_token: '{{AT}}' } } },
      ];
    }
    return [
      { id: 'ip-signin', from: 'user', to: 'browser', label: 'Signs in from a hotel', title: 'Sign-in from somewhere new', det: 'human', desc: 'The user is travelling and connects through a free VPN.' },
      ...common,
      { id: 'ip-score', from: 'entra', to: 'risk', label: 'Score this sign-in', title: 'ID Protection scores the sign-in', det: 'policy', desc: 'Real-time detections run during the sign-in.' },
      { id: 'ip-score-res', from: 'risk', to: 'entra', label: 'Sign-in risk: medium', title: 'Medium sign-in risk', det: 'policy', desc: 'Two detections fired. Neither proves an attack, which is exactly what medium means.', kv: { signInRiskLevel: 'medium', detections: 'anonymizedIPAddress, unfamiliarFeatures' } },
      { id: 'ip-policy', from: 'entra', to: 'entra', label: 'Require MFA', title: 'Risk policy asks for MFA', det: 'policy', desc: 'Medium or high sign-in risk requires MFA, and sign-in frequency is set to every time for risky sign-ins.', checks: [{ name: 'Policy: medium+ sign-in risk requires MFA', ok: true }] },
      { id: 'ip-mfa', from: 'entra', to: 'user', label: 'MFA prompt', title: 'User completes MFA', det: 'human', desc: 'An attacker with only the password would stop here.' },
      { id: 'ip-remediate', from: 'entra', to: 'risk', label: 'Risk remediated', title: 'MFA clears the sign-in risk', det: 'policy', desc: 'Passing MFA remediates the sign-in risk, and the detections close.', checks: [{ name: 'Sign-in risk state', ok: true, detail: 'remediated' }] },
      { id: 'ip-token', from: 'entra', to: 'browser', label: 'Tokens', title: 'Sign-in completes', det: 'protocol', desc: '', res: { status: 200, statusText: 'OK', json: { access_token: '{{AT}}' } } },
    ];
  },
});
