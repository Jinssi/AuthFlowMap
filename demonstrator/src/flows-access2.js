'use strict';
/* =====================================================================
   FLOW DEFINITIONS: access, MFA, devices and risk (part 2: phishing)
   ===================================================================== */
const PHISH = 'https://login.contoso-support.com';

FLOWS.push({
  id: 'aitm', group: 'access', icon: '🎣', live: true,
  title: 'Session theft and phishing-resistant MFA',
  subtitle: 'An attacker-in-the-middle phishing kit against push MFA, a passkey and token protection.',
  actors: ['user', 'attacker', 'entra', 'graph'],
  layout: { user: [110, 90], attacker: [480, 380], entra: [860, 90], graph: [860, 380] },
  variants: [
    { id: 'push', label: 'Password + push MFA', desc: 'The kit relays everything. The user approves the push and the attacker walks away with the session.' },
    { id: 'passkey', label: 'Passkey', desc: 'The passkey is bound to login.microsoft.com. On the fake site it won\'t sign anything.' },
    { id: 'bound', label: 'Push MFA + token protection', desc: 'The attacker still steals the session, but it only works on the device it was issued to.' },
    { id: 'network', label: 'Push MFA + compliant network', desc: 'The kit relays the password and the push, but its sign-in doesn\'t come through Contoso\'s Global Secure Access, so Conditional Access refuses it.' },
  ],
  brief: {
    what: 'MFA stops password spraying. It doesn\'t stop a phishing kit that sits between the user and the real sign-in page, because push, SMS and one-time codes can all be relayed. This tab plays the same attack four times. With push MFA the attacker gets a working session. With a <b>passkey</b> the browser refuses, because the credential only signs for the real origin. With <b>token protection</b> and a compliant-device policy, the stolen session is useless anywhere but the user\'s own device. With the <b>compliant network</b> check, Entra only accepts sign-ins and token requests that came through Contoso\'s own Global Secure Access, so the kit\'s relayed sign-in fails.',
    prereqs: ['Passkeys, Windows Hello for Business or certificate-based auth registered for users', 'A Conditional Access authentication strength that requires phishing-resistant MFA', 'Token protection in Conditional Access for supported apps, and a compliant-device requirement', 'For the compliant network variant: the Global Secure Access client with the Microsoft traffic profile on every device users sign in from, signaling for Conditional Access turned on, and a policy that blocks access outside <i>All Compliant Network locations</i>'],
    antiPattern: 'Calling any MFA "phishing-resistant". Number matching helps against push fatigue, but a relayed session is still a perfectly valid sign-in.',
    verify: 'Nobody gets phished in Live mode. It signs you in, lists the methods registered on your account, marks which ones resist phishing and shows the <code>amr</code> values in your real token.',
  },
  tokens: (ctx) => ({
    ST: { label: 'Stolen access token', ...TK.graphUser(ctx.t, { appid: '00000002-0000-0ff1-ce00-000000000000', scp: 'Mail.ReadWrite', appName: 'Outlook on the web', appidacr: '0', extra: { amr: ['pwd', 'mfa'], ipaddr: '198.51.100.77' } }) },
  }),
  steps: (ctx) => {
    const v = ctx.variant || 'push';
    const s = [
      { id: 'ph-lure', from: 'attacker', to: 'user', label: 'Email: "Your mailbox is full"', title: 'Phishing email arrives', det: 'human', desc: 'The link points to the attacker\'s domain. The page will look exactly like the Microsoft sign-in.' },
      { id: 'ph-visit', from: 'user', to: 'attacker', label: `GET ${PHISH}`, title: 'User opens the fake page', det: 'human', desc: 'The browser address bar shows the attacker\'s domain. Most people never look.', req: { method: 'GET', url: `${PHISH}/common/oauth2/v2.0/authorize` } },
      { id: 'ph-relay', from: 'attacker', to: 'entra', label: 'Relays the real page', title: 'Kit fetches the real sign-in page', det: 'protocol', desc: 'The kit proxies login.microsoftonline.com live, so branding, the user\'s name and even the MFA prompt all look right.' },
    ];
    if (v === 'passkey') {
      return [...s,
        { id: 'ph-webauthn', from: 'entra', to: 'attacker', label: 'WebAuthn challenge', title: 'Entra asks for the passkey', det: 'protocol', desc: 'Entra sends a challenge for relying party <code>login.microsoft.com</code>. The kit passes it on to the user\'s browser.', kv: { rpId: 'login.microsoft.com', challenge: '{{state}}' } },
        { id: 'ph-origin', from: 'user', to: 'user', decider: 'browser', label: 'Origin check fails', title: 'The browser refuses to use the passkey', det: 'protocol', desc: 'The browser, not the user, compares the page origin with the passkey\'s relying party. The page is contoso-support.com, so there\'s no matching credential to use.',
          why: 'This check happens in code. It doesn\'t depend on the user spotting the fake domain.',
          checks: [{ name: 'Page origin matches the passkey\'s relying party', ok: false, detail: `${PHISH} is not login.microsoft.com` }, { name: 'Signed assertion produced', ok: false }] },
        { id: 'ph-nothing', from: 'attacker', to: 'attacker', label: 'Nothing to steal', title: 'The kit gets nothing usable', det: 'protocol', status: 'error', desc: 'No signature, no session cookie, no token. At most the attacker has a username.' },
      ];
    }
    s.push(
      { id: 'ph-password', from: 'user', to: 'attacker', label: 'Types password', title: 'User enters the password', det: 'human', desc: 'The kit stores it and forwards it to Entra.', req: { method: 'POST', url: `${PHISH}/common/login`, form: { login: ID.user.upn, passwd: '••••••••[captured]' } } },
      { id: 'ph-fwd', from: 'attacker', to: 'entra', label: 'Forwards password', title: 'Kit signs in as the user', det: 'protocol', desc: 'From Entra\'s side this is the user signing in, just from an odd IP address.' },
      { id: 'ph-push', from: 'entra', to: 'user', label: 'Push: enter 42', title: 'Real MFA prompt on the phone', det: 'human', desc: 'Entra sends a genuine push with number matching. The kit shows the number on the fake page, so it all adds up for the user.' },
      { id: 'ph-approve', from: 'user', to: 'entra', label: 'Approves', title: 'User approves', det: 'human', desc: 'The push can\'t tell which website asked for it. That\'s the whole weakness.', why: 'Push, SMS, voice and OTP codes prove the user is present. None of them prove which site the user is looking at.' },
    );
    if (v === 'network') {
      return [...s,
        { id: 'ph-cn', from: 'entra', to: 'entra', label: 'CA: compliant network?', title: 'Conditional Access checks how the sign-in arrived', det: 'policy',
          desc: 'Password and MFA both passed, but Conditional Access runs before Entra issues anything. This sign-in reached Entra from the kit\'s server, not through Contoso\'s Global Secure Access, so it isn\'t in the compliant network.',
          why: 'The compliant network is specific to the tenant. Running Global Secure Access in a tenant of their own doesn\'t help the attacker pass Contoso\'s check.',
          checks: [{ name: 'Password and MFA', ok: true, detail: 'Relayed by the kit' }, { name: 'Policy: block outside All Compliant Network locations', ok: false, detail: 'Sign-in came from the kit\'s server' }] },
        { id: 'ph-cn-block', from: 'entra', to: 'attacker', label: 'Blocked: AADSTS53003', title: 'No session and no tokens for the kit', det: 'policy', status: 'error',
          desc: 'Entra refuses to finish the sign-in. The kit relays the error page, so the user sees "You can\'t access this right now" and nothing lands in the attacker\'s proxy.',
          kv: { error: 'AADSTS53003', meaning: 'Access has been blocked by Conditional Access policies' } },
        { id: 'ph-cn-left', from: 'attacker', to: 'attacker', label: 'Only the password', title: 'The attacker keeps the password, nothing more', det: 'protocol',
          desc: 'Tokens taken some other way, for example by malware on a laptop, fail the same check whenever they\'re used outside the tunnel. The <a href="#flow/gsa-compliant-network">compliant network tab</a> plays that replay. The password is still stolen, so reset it and move users to passkeys, which stop the relay itself.' },
      ];
    }
    s.push(
      { id: 'ph-cookie', from: 'entra', to: 'attacker', label: 'Session cookie + tokens', title: 'Entra issues the session to the kit', det: 'protocol', desc: 'Password and MFA both passed, so Entra sets the session cookie. It lands in the attacker\'s proxy.', res: { status: 302, statusText: 'Found', headers: { 'Set-Cookie': 'ESTSAUTHPERSISTENT=0.AR8A…[captured]; secure; HttpOnly' } } },
      { id: 'ph-redirect', from: 'attacker', to: 'user', label: 'Redirect to real Outlook', title: 'User lands in the real mailbox', det: 'protocol', desc: 'Nothing looks wrong to the user.' },
    );
    if (v === 'bound') {
      return [...s,
        { id: 'ph-replay', from: 'attacker', to: 'entra', label: 'Replays session from own laptop', title: 'Attacker tries to use the stolen session', det: 'protocol', desc: 'The attacker loads the cookie into its own browser and asks Entra for a token.' },
        { id: 'ph-block', from: 'entra', to: 'attacker', label: 'Blocked', title: 'Entra refuses the replay', det: 'policy', status: 'error',
          desc: 'Token protection binds the session to the device key of the original sign-in. The attacker\'s laptop can\'t produce that proof, and it isn\'t a compliant device either.',
          why: 'Token protection currently covers specific apps and platforms. Pair it with a compliant-device requirement so an unknown device fails even where binding isn\'t supported yet.',
          checks: [{ name: 'Session bound to device key, proof of possession', ok: false, detail: 'Attacker device can\'t sign with the original key' }, { name: 'Device is compliant', ok: false, detail: 'Unknown device' }],
          res: { status: 400, statusText: 'Bad Request', json: { error: 'invalid_grant', error_description: 'AADSTS53003: Access has been blocked by Conditional Access policies.' } } },
      ];
    }
    return [...s,
      { id: 'ph-replay', from: 'attacker', to: 'graph', label: 'GET /me/messages', title: 'Attacker reads the mailbox', det: 'protocol', desc: 'From the attacker\'s own laptop, with the stolen session. Nothing ties it to the user\'s device.', req: { method: 'GET', url: `${GRAPH}/v1.0/me/messages?$top=50`, headers: HDR.bearer('ST') } },
      { id: 'ph-breach', from: 'graph', to: 'attacker', label: '200 mail', title: 'Breach', det: 'protocol', status: 'error', desc: 'The token is valid, so Graph serves it. Typical next steps are inbox rules and invoice fraud.', res: { status: 200, statusText: 'OK', json: { value: [{ subject: 'Q3 supplier bank details' }, { subject: 'Wire approval PO-10442' }] } } },
    ];
  },
});
