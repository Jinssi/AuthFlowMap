'use strict';
/* =====================================================================
   FLOW DEFINITIONS: access, MFA, devices and risk (part 3: devices)
   ===================================================================== */
FLOWS.push({
  id: 'device-sso', group: 'access', icon: '💻', live: true,
  title: 'Device identity and single sign-on',
  subtitle: 'A managed laptop signs in silently and proves what it is. An unknown device gets prompted and restricted.',
  actors: ['user', 'pc', 'browser', 'intune', 'entra', 'graph'],
  layout: { user: [110, 80], pc: [110, 330], browser: [480, 400], intune: [480, 80], entra: [860, 200], graph: [860, 420] },
  variants: [
    { id: 'managed', label: 'Managed, compliant laptop', desc: 'Entra joined, enrolled in Intune, signed in with Windows Hello. The browser rides on the device\'s PRT.' },
    { id: 'unknown', label: 'Unknown home PC', desc: 'No device identity at all. Entra only knows a browser showed up.' },
  ],
  brief: {
    what: 'A registered or joined device has its own identity in Entra. When a user signs in to Windows, the device gets a <b>Primary Refresh Token</b> whose key lives in the TPM. Edge, and Chrome with the Windows accounts extension, use it for single sign-on and to prove which device they\'re on. That\'s how Conditional Access can require a <b>compliant device</b>, and how the token ends up with a <code>deviceid</code> claim. An unknown device can\'t prove anything, so it lands on whatever your policy allows unmanaged devices.',
    prereqs: ['Devices Entra joined, hybrid joined or registered', 'Intune compliance policies', 'Conditional Access that requires a compliant device, or allows unmanaged devices only in the browser with app-enforced restrictions', 'Edge, or Chrome with the Windows accounts extension, on Windows'],
    antiPattern: 'Treating "has MFA" as enough for full access from any device. A stolen session or an infected home PC then gets the same access as a patched company laptop.',
    verify: 'Live mode signs you in from this browser and shows whether the token carries a <code>deviceid</code>. On a managed Windows device with Edge you should see one. From an unmanaged browser you won\'t.',
  },
  tokens: (ctx) => ({
    AT: { label: 'Access token (aud = Graph)', ...TK.graphUser(ctx.t, { appid: '00000002-0000-0ff1-ce00-000000000000', scp: 'Mail.ReadWrite', appName: 'Outlook on the web', appidacr: '0', extra: ctx.variant === 'unknown' ? { amr: ['pwd', 'mfa'] } : { amr: ['mfa'], deviceid: 'b7e4c2a1-9f3d-4e6a-8c1b-2d5f7a9e0c34' } }) },
  }),
  steps: (ctx) => {
    if (ctx.variant === 'unknown') {
      return [
        { id: 'dv-open', from: 'user', to: 'browser', label: 'Opens Outlook on the web', title: 'User opens Outlook from a home PC', det: 'human', desc: 'Any browser on a machine the company knows nothing about.' },
        { id: 'dv-authz', from: 'browser', to: 'entra', label: 'GET /authorize, no PRT', title: 'Browser starts sign-in with nothing to show', det: 'protocol', desc: 'No PRT cookie and no device certificate. Entra can\'t tell this device from any other.', req: { method: 'GET', url: AUTHZ_EP, query: { client_id: '00000002-0000-0ff1-ce00-000000000000', response_type: 'code', scope: 'openid profile Mail.ReadWrite' } } },
        { id: 'dv-signin', from: 'entra', to: 'user', label: 'Password + MFA', title: 'User gets the full prompt', det: 'human', desc: 'No device, no SSO. The user types the password and approves MFA.' },
        { id: 'dv-policy', from: 'entra', to: 'entra', label: 'Unmanaged device policy', title: 'Conditional Access treats it as unmanaged', det: 'policy', desc: 'Here the policy allows the browser only, with app-enforced restrictions and a one hour sign-in frequency. Another tenant might block outright.',
          checks: [{ name: 'Device identity presented', ok: false, detail: 'Unknown device' }, { name: 'MFA', ok: true }, { name: 'Client app is a browser', ok: true }, { name: 'Session: app-enforced restrictions, sign-in frequency 1 hour', ok: true }] },
        { id: 'dv-token-res', from: 'entra', to: 'browser', label: 'Token, no deviceid', title: 'Restricted session issued', det: 'protocol', desc: 'The token has no <code>deviceid</code>. Outlook on the web switches to read-only attachments.', res: { status: 200, statusText: 'OK', json: { access_token: '{{AT}}', token_type: 'Bearer' } } },
        { id: 'dv-graph-req', from: 'browser', to: 'graph', label: 'Download attachment', title: 'User tries to download a file', det: 'protocol', desc: '', req: { method: 'GET', url: `${GRAPH}/v1.0/me/messages/AAMk…/attachments/AAMk…/$value`, headers: HDR.bearer('AT') } },
        { id: 'dv-graph-res', from: 'graph', to: 'browser', label: 'Blocked by session policy', title: 'Download blocked, viewing allowed', det: 'policy', status: 'error', desc: 'App-enforced restrictions let the user read in the browser but not save files to an unknown device.', res: { status: 403, statusText: 'Forbidden', json: { error: { code: 'AccessDenied', message: 'Downloads are blocked on unmanaged devices by your organization\'s policy.' } } } },
        { id: 'dv-desktop', from: 'user', to: 'entra', label: 'Tries Outlook desktop', title: 'Desktop app from the same PC', det: 'human', desc: 'The desktop client needs a compliant device under this policy.', res: { status: 400, statusText: 'Bad Request', json: { error: 'invalid_grant', error_description: 'AADSTS53000: Device is not in required device state: compliant.' } }, status: 'error' },
      ];
    }
    return [
      { id: 'dv-logon', from: 'user', to: 'pc', label: 'Windows Hello', title: 'User signs in to Windows', det: 'human', desc: 'Face or PIN. Windows Hello is phishing-resistant MFA on its own.' },
      { id: 'dv-prt-req', from: 'pc', to: 'entra', label: 'Request PRT (TPM-signed)', title: 'Device asks for a Primary Refresh Token', det: 'protocol', desc: 'The request is signed with the device key and the user\'s Windows Hello key. Both keys live in the TPM.' },
      { id: 'dv-prt-res', from: 'entra', to: 'pc', label: 'PRT + session key', title: 'Entra issues the PRT', det: 'protocol', desc: 'The PRT carries the device ID and the fact that the user did MFA. Its session key is encrypted to the TPM, so copying the file to another machine gets you nothing.' },
      { id: 'dv-compliance', from: 'intune', to: 'entra', label: 'Device compliant', title: 'Intune reports compliance', det: 'policy', desc: 'Intune checked BitLocker, OS version and Defender and marked the device object compliant.', checks: [{ name: 'BitLocker on', ok: true }, { name: 'OS patched', ok: true }, { name: 'Defender healthy', ok: true }] },
      { id: 'dv-open', from: 'user', to: 'browser', label: 'Opens Outlook on the web', title: 'User opens Outlook in Edge', det: 'human', desc: 'Same app as the unknown-device variant.' },
      { id: 'dv-authz', from: 'browser', to: 'entra', label: 'GET /authorize + PRT cookie', title: 'Edge adds the PRT cookie', det: 'protocol', desc: 'Windows gives Edge a short-lived cookie signed with the PRT session key. Only this TPM could have produced it.', req: { method: 'GET', url: AUTHZ_EP, headers: { Cookie: 'x-ms-RefreshTokenCredential=eyJhbGciOiJIUzI1NiIs…[signed by TPM session key]' }, query: { client_id: '00000002-0000-0ff1-ce00-000000000000', response_type: 'code', scope: 'openid profile Mail.ReadWrite' } } },
      { id: 'dv-policy', from: 'entra', to: 'entra', label: 'Device + MFA satisfied', title: 'Conditional Access passes without a prompt', det: 'policy', desc: 'The device is known and compliant, and the PRT already carries MFA. Nothing to ask the user.',
        checks: [{ name: 'Device identity from PRT', ok: true }, { name: 'Device compliant', ok: true }, { name: 'MFA claim in PRT', ok: true, detail: 'Windows Hello' }] },
      { id: 'dv-token-res', from: 'entra', to: 'browser', label: 'Token with deviceid', title: 'Silent sign-in', det: 'protocol', desc: 'The user never saw a prompt. The token carries <code>deviceid</code>.', res: { status: 200, statusText: 'OK', json: { access_token: '{{AT}}', token_type: 'Bearer' } } },
      { id: 'dv-graph-req', from: 'browser', to: 'graph', label: 'Download attachment', title: 'User downloads a file', det: 'protocol', desc: '', req: { method: 'GET', url: `${GRAPH}/v1.0/me/messages/AAMk…/attachments/AAMk…/$value`, headers: HDR.bearer('AT') } },
      { id: 'dv-graph-res', from: 'graph', to: 'browser', label: '200 file', title: 'Full access', det: 'protocol', desc: 'A managed device gets the full experience.', res: { status: 200, statusText: 'OK', text: '%PDF-1.7 …' } },
    ];
  },
});
