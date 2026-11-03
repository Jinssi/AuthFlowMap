'use strict';
/* =====================================================================
   FLOW DEFINITIONS: Global Secure Access and Zero Trust (part 1)
   Private Access, Internet Access and the explicit forward proxy.
   Sources: the Global Secure Access offering blog (Nov 2026), "Secure AI, web, and private apps with
   Zero Trust", and the Learn pages they link: Private Access, connectors, connector groups, home network
   support, traffic forwarding, web filtering, cloud firewall, threat intelligence, explicit forward proxy.
   Global Secure Access works on network connections, not HTTP APIs you call yourself, so most steps
   show values instead of requests, and the client's tokens show their audience and lifetime, not a decode.
   ===================================================================== */
{
  const ERP = 'erp01.corp.contoso.com';
  const ERP_APP = 'Finance ERP (per-app access)';
  const WIKI = 'wiki.corp.contoso.com';

  /* ---------- Private Access ---------- */
  // The client's tunnel, the edge's checks and the connector hop, shared by the variants that reach a private app.
  const privatePath = (p, app, host, port, extra = {}) => [
    { id: `${p}-tunnel`, from: 'gsaClient', to: 'sse', label: 'Tunnel + token', title: 'Client tunnels the connection to the edge', det: 'protocol', desc: `The client sends the ${host} connection through its Private Access tunnel to the nearest Global Secure Access edge and presents the token it just got.` },
    { id: `${p}-edge`, from: 'sse', to: 'sse', label: 'Token valid, app segment matches', title: 'The edge checks the token and the app segment', det: 'policy', desc: `Two questions. Is the token genuine, current and meant for the ${app} app? Is ${host}:${port} one of that app's segments? Both yes, so the edge picks the app's connector group.`,
      why: extra.why,
      checks: [{ name: `Token signature, issuer and audience (${app} app)`, ok: true, kind: 'token' }, { name: 'Token not expired', ok: true, kind: 'token' }, { name: `${host}:${port} is in the ${app} app segment`, ok: true }, { name: 'Connector group for the app: HQ datacenter', ok: true }] },
    { id: `${p}-connector`, from: 'sse', to: 'connector', label: 'Over the connector\'s outbound link', title: 'The edge hands the connection to a connector', det: 'protocol', desc: 'Connectors only make outbound connections, so Contoso opened no inbound port in its firewall. Within the connector group, session affinity keeps requests from the same user and device on the same connector for the whole session.', kv: { connectorGroup: 'HQ datacenter', loadBalancing: 'Session affinity' } },
    { id: `${p}-app`, from: 'connector', to: 'privApp', label: `TCP ${port}`, title: 'The connector opens the connection inside the network', det: 'protocol', desc: `To ${host} the connector is an ordinary internal client. The server sees the connector's address, never the laptop's.` },
  ];
  const paToken = (p, app, policyChecks, desc) => [
    { id: `${p}-token`, from: 'gsaClient', to: 'entra', label: `Token for ${app} app`, title: 'Client asks Entra for a token for the app', det: 'protocol', desc: `Every Private Access app, Quick Access or per-app, is an enterprise app in Entra. The client asks for a token for the ${app} app as the signed-in user on this device. Conditional Access runs on that request, exactly as it would for a SaaS app.` },
    { id: `${p}-ca`, from: 'entra', to: 'entra', label: `Conditional Access for ${app}`, title: `Entra applies the policies that target ${app}`, det: 'policy', desc, checks: policyChecks },
  ];

  FLOWS.push({
    id: 'gsa-private-access', group: 'gsa', icon: '🔌', live: false,
    preview: 'Home network support and multiple Private Access traffic forwarding profiles are in preview.',
    title: 'Private Access instead of a VPN',
    subtitle: 'Per-app access to an on-premises server over RDP, with Conditional Access on the app and no inbound firewall port.',
    actors: ['user', 'pc', 'byodPc', 'printer', 'gsaClient', 'entra', 'sse', 'connector', 'privApp'],
    layout: { user: [110, 70], pc: [110, 250], byodPc: [110, 420], printer: [400, 520], gsaClient: [400, 330], entra: [400, 70], sse: [690, 200], connector: [970, 330], privApp: [970, 70] },
    variants: [
      { id: 'managed', label: 'Managed laptop', desc: 'Alex connects to the finance ERP server over RDP from a café. No VPN, one app, one policy.' },
      { id: 'byod', label: 'Personal laptop (BYOD)', desc: 'The same user on an unmanaged laptop. The intranet wiki lets them in with MFA. The finance ERP server wants a compliant device and says no.' },
      { id: 'home', label: 'At home with a printer', desc: 'Home network support sends printer traffic straight to the local subnet while the ERP connection stays in the tunnel.' },
    ],
    brief: {
      what: 'A VPN puts the whole laptop on the network. <b>Microsoft Entra Private Access</b>, one half of Global Secure Access, publishes private apps instead. The <b>Global Secure Access client</b> tunnels only the hosts and ports of the apps a user is assigned to. Each app is an enterprise app in Entra with its own Conditional Access policy, so the same users, groups and policies you use for SaaS apply, with nothing to sync. A <b>private network connector</b> next to the server makes outbound connections only. Any TCP or UDP app works, RDP and SMB as well as web apps, and the app doesn\'t change. <b>Quick Access</b> covers a broad set of FQDNs and IP ranges in one app. <b>Per-app access</b> gives a sensitive server, like this ERP server, an app and a policy of its own.',
      prereqs: ['Entra ID P1 for each user, plus Private Access, Global Secure Access or Entra Suite licences', 'Private network connectors on servers that can reach the app, in a connector group. Each connector registers with Entra and gets its own certificate', `A per-app Global Secure Access app for <code>${ERP}</code> on TCP 3389, with users and groups assigned`, 'The Private Access traffic forwarding profile enabled, and the client on the devices', 'Conditional Access policies with the app as the target resource'],
      antiPattern: 'Moving the whole VPN address space into one Quick Access app and stopping there. That keeps the reach of a VPN. Use Quick Access to retire the VPN, then give sensitive servers their own per-app access and a stricter policy.',
      verify: 'Simulated only. The client gets its tokens from Entra through Windows, so the tab shows each token\'s audience and lifetime rather than decoding it.',
    },
    steps: (ctx) => {
      if (ctx.variant === 'byod') {
        return [
          { id: 'pb-wiki', from: 'user', to: 'byodPc', label: `Open ${WIKI}`, title: 'User opens the intranet wiki', det: 'human', desc: 'Alex works from a personal Windows laptop today. Installing the Global Secure Access client registered the device in Entra. On Windows BYOD the client offers the Private Access profile only.' },
          { id: 'pb-acquire', from: 'byodPc', to: 'gsaClient', label: `TCP ${WIKI}:443`, title: 'Client acquires the wiki connection', det: 'protocol', desc: 'The wiki is its own Private Access app, so the client tunnels the connection.', kv: { destination: `${WIKI}:443`, profile: 'Private Access', app: 'Intranet wiki' } },
          ...paToken('pb-w', 'Intranet wiki', [{ name: 'Policy target resource: Intranet wiki', ok: true }, { name: 'Grant: MFA', ok: true, detail: 'Passkey in Authenticator' }, { name: 'Device: Entra registered, not compliant', ok: true, detail: 'This policy doesn\'t ask for a compliant device' }],
            'The wiki\'s policy asks for MFA and nothing about the device, so an unmanaged laptop is fine. That\'s how contractors and employees on their own devices get to the apps they need.'),
          { id: 'pb-w-ok', from: 'entra', to: 'gsaClient', label: 'Access token', title: 'Token for the wiki', det: 'protocol', desc: '', kv: { audience: 'Intranet wiki (Private Access app)', lifetime: '60 to 90 minutes' } },
          { id: 'pb-w-tunnel', from: 'gsaClient', to: 'sse', label: 'Tunnel + token', title: 'Wiki connection goes through', det: 'protocol', desc: 'The edge checks the token and the app segment and passes the connection to a connector, as in the managed laptop variant.' },
          { id: 'pb-erp', from: 'user', to: 'byodPc', label: `mstsc ${ERP}`, title: 'User tries the finance ERP server', det: 'human', desc: 'Same laptop, same user, different app.' },
          ...paToken('pb-e', 'Finance ERP', [{ name: `Policy target resource: ${ERP_APP}`, ok: true }, { name: 'Grant: MFA', ok: true }, { name: 'Grant: compliant device', ok: false, detail: 'Entra registered, not managed by Intune' }],
            'The ERP server holds financial data, so its policy also requires a compliant device. A personal laptop can\'t be compliant.'),
          { id: 'pb-e-block', from: 'entra', to: 'gsaClient', label: 'Blocked: AADSTS53000', title: 'No token for the ERP app', det: 'policy', status: 'error', desc: 'Without a token there is no tunnel for this app, so not one packet reaches the datacenter. The user sees why in the client.', kv: { error: 'AADSTS53000', meaning: 'Device is not in required device state: compliant' } },
        ];
      }
      if (ctx.variant === 'home') {
        return [
          { id: 'ph-print', from: 'user', to: 'pc', label: 'Print to home printer', title: 'User prints at home', det: 'human', desc: 'Alex is working from home with Private Access connected and sends a document to the printer on the home network.' },
          { id: 'ph-acquire', from: 'pc', to: 'gsaClient', label: 'TCP 192.168.1.20:9100', title: 'Client sees a local address', det: 'protocol', desc: 'The printer is on the home subnet.' },
          { id: 'ph-bypass', from: 'gsaClient', to: 'gsaClient', label: 'Local subnet bypass?', title: 'Client checks home network support', det: 'protocol', desc: 'The client works out the local subnet. Intelligent Local Access comes first, then the home network bypass, then normal Private Access acquisition.',
            why: 'If a home subnet overlaps a corporate range, the local path wins and that corporate resource is unreachable until the user turns Prefer Local Network off. Advanced Diagnostics in the client shows which path a connection took.',
            checks: [{ name: 'Prefer Local Network turned on in the client', ok: true }, { name: 'Allow local subnet bypass on the Private Access profile', ok: true, detail: 'An admin setting' }, { name: '192.168.1.20 is in the local subnet 192.168.1.0/24', ok: true }] },
          { id: 'ph-direct', from: 'gsaClient', to: 'printer', label: 'Direct, not tunneled', title: 'Printer traffic stays at home', det: 'protocol', desc: 'The client sends it straight to the printer. Private Access stays connected, so the user doesn\'t have to switch anything off to print.' },
          { id: 'ph-erp', from: 'user', to: 'pc', label: `mstsc ${ERP}`, title: 'User opens the ERP server', det: 'human', desc: 'A minute later, from the same laptop.' },
          { id: 'ph-erp-acq', from: 'pc', to: 'gsaClient', label: `TCP ${ERP}:3389`, title: 'This one is acquired', det: 'protocol', desc: 'Not a local address, and it matches the ERP app segment, so it goes into the tunnel with the token and policy from the managed laptop variant.' },
          ...privatePath('ph', 'Finance ERP', ERP, 3389),
        ];
      }
      return [
        { id: 'pa-open', from: 'user', to: 'pc', label: `mstsc ${ERP}`, title: 'User opens Remote Desktop', det: 'human', desc: `${ID.user.name} opens Remote Desktop to the finance ERP server from a café. There is no VPN to start.` },
        { id: 'pa-acquire', from: 'pc', to: 'gsaClient', label: `TCP ${ERP}:3389`, title: 'Client acquires the connection', det: 'protocol', desc: `Traffic forwarding profiles are checked in order: Microsoft, then Private Access, then Internet Access. The Finance ERP app lists <code>${ERP}</code> on TCP 3389, so the client takes this connection. Anything that isn't in an app segment is left alone.`, kv: { destination: `${ERP}:3389`, profile: 'Private Access', app: ERP_APP } },
        ...paToken('pa', 'Finance ERP', [{ name: `Policy target resource: ${ERP_APP}`, ok: true }, { name: 'User assigned to the app', ok: true, detail: 'Finance group' }, { name: 'Grant: MFA', ok: true, detail: 'Windows Hello at sign-in' }, { name: 'Grant: compliant device', ok: true, detail: 'Intune: compliant' }],
          'The policy was created from the app\'s own Conditional Access page, so the app is its target resource. It uses the same Finance group and the same compliant-device grant as Contoso\'s SaaS policies.'),
        { id: 'pa-token-res', from: 'entra', to: 'gsaClient', label: 'Access token', title: 'Token for the ERP app', det: 'protocol', desc: 'The client keeps it for this tunnel and refreshes it before it expires.', kv: { audience: `${ERP_APP} app`, lifetime: '60 to 90 minutes' } },
        ...privatePath('pa', 'Finance ERP', ERP, 3389, { why: 'A VPN would have put the laptop on the whole network. Per-app access gives this user this host and this port. Malware on the laptop can\'t reach the rest of the datacenter through the tunnel.' }),
        { id: 'pa-session', from: 'privApp', to: 'pc', label: 'RDP session', title: 'Remote Desktop session is up', det: 'protocol', desc: 'Replies take the same path back. The ERP server didn\'t change: no agent, no OAuth, no CAE support. The Universal CAE tab shows what happens if the laptop falls out of compliance mid-session.' },
      ];
    },
  });

  /* ---------- Internet Access ---------- */
  const IA_TARGET = 'All internet resources with Global Secure Access';
  const iaSetup = () => [
    { id: 'ia-token', from: 'gsaClient', to: 'entra', label: 'Token for Internet Access', title: 'At sign-in: client gets its tunnel token', det: 'protocol', desc: 'This happened once when Alex signed in, not per request. Conditional Access runs on it.' },
    { id: 'ia-ca', from: 'entra', to: 'entra', label: 'CA links security profiles', title: 'Conditional Access links the security profiles', det: 'policy',
      desc: `A policy targets <i>${IA_TARGET}</i> and links the <b>Finance overrides</b> security profile in its session controls. The <b>baseline</b> profile applies to everyone without a policy.`,
      checks: [{ name: `Policy target resource: ${IA_TARGET}`, ok: true }, { name: 'User in Finance group', ok: true }, { name: 'Session control: security profile "Finance overrides" (priority 100)', ok: true }, { name: 'Baseline profile: applies to all traffic, evaluated last', ok: true }] },
    { id: 'ia-token-res', from: 'entra', to: 'gsaClient', label: 'Access token', title: 'Tunnel token issued', det: 'protocol', desc: '', kv: { audience: 'Global Secure Access, Internet Access profile', lifetime: '60 to 90 minutes' } },
  ];
  const blockPage = (p, label, title, desc, kv) => ({ id: `${p}-block`, from: 'sse', to: 'pc', label, title, det: 'policy', stage: 'authorize', status: 'error', desc, kv });

  FLOWS.push({
    id: 'gsa-internet-access', group: 'gsa', icon: '🌎', live: false,
    preview: 'The Continue default action and the cloud firewall for clients are in preview.',
    title: 'Internet Access: security profiles',
    subtitle: 'Conditional Access decides which web filtering, threat intelligence and firewall rules apply to whom, and the edge enforces them on every connection.',
    actors: ['user', 'pc', 'gsaClient', 'entra', 'sse', 'web'],
    layout: { user: [110, 70], pc: [110, 330], gsaClient: [400, 330], entra: [400, 70], sse: [690, 200], web: [970, 330] },
    variants: [
      { id: 'allow', label: 'Exception for one group', desc: 'A URL that the baseline would block is allowed for Finance by a small profile above it.' },
      { id: 'continue', label: 'Continue to the baseline', desc: 'Nothing in the Finance profile matches, so evaluation continues to the baseline, which blocks the category.' },
      { id: 'threat', label: 'Threat intelligence', desc: 'A phishing link passes web filtering and is blocked by threat intelligence.' },
      { id: 'firewall', label: 'Cloud firewall (SSH)', desc: 'A non-web connection on TCP 22 is acquired with Custom Acquire and blocked by a cloud firewall rule.' },
    ],
    brief: {
      what: '<b>Microsoft Entra Internet Access</b> is the identity-aware secure web gateway half of Global Secure Access. The client tunnels internet traffic to the edge, and <b>Conditional Access</b> decides which <b>security profiles</b> apply to whom: a policy targets <i>All internet resources with Global Secure Access</i> and links a profile in its session controls. Inside a profile the controls run in a fixed order: TLS inspection, web content filtering, threat intelligence, file type, DLP, third-party. Profiles run in priority order. With the <b>Continue</b> default action, a profile with no matching rule hands the request to the next one, so a small exception profile for one group can sit above a shared <b>baseline</b> without copying it. The <b>cloud firewall</b> adds Allow and Block rules on destinations, ports and protocols beyond the web.',
      prereqs: ['Entra ID P1 and Internet Access, Global Secure Access or Entra Suite licences', 'The Internet Access traffic forwarding profile enabled and the client on the devices. Default Acquire takes TCP 80 and 443 only', 'Security profiles with web filtering policies, and a baseline profile whose default action is Allow or Block', `A Conditional Access policy that targets <i>${IA_TARGET}</i> and links the profile`, 'For other ports: a Custom Acquire rule and cloud firewall rules. Configuring them needs the Global Secure Access Administrator and Conditional Access Administrator roles'],
      antiPattern: 'A second policy console with its own copy of your users and groups. Internet Access uses the groups and Conditional Access you already have, so an exception for Finance is a profile linked to the Finance group, not another rule set to keep in step.',
      verify: 'Simulated only. The block page is shown for TLS-inspected traffic, and admins can customise its text. The traffic logs name the profile, policy and rule that decided.',
    },
    steps: (ctx) => {
      const v = ctx.variant;
      if (v === 'firewall') {
        return [
          ...iaSetup(),
          { id: 'fw-ssh', from: 'user', to: 'pc', label: 'ssh admin@198.51.100.7', title: 'User opens an SSH session', det: 'human', desc: 'Alex tries to reach a server on the internet over SSH.' },
          { id: 'fw-acquire', from: 'pc', to: 'gsaClient', label: 'TCP 198.51.100.7:22', title: 'Custom Acquire takes TCP 22', det: 'protocol', desc: 'Default Acquire only covers TCP 80 and 443. Contoso added a Custom Acquire rule for TCP 22, so this connection goes to the edge too. Acquiring traffic doesn\'t allow or block it. That\'s the firewall\'s job.', kv: { policy: 'Custom Acquire', destination: '198.51.100.7:22' } },
          { id: 'fw-tunnel', from: 'gsaClient', to: 'sse', label: 'Tunnel', title: 'Connection reaches the edge', det: 'protocol', desc: '' },
          { id: 'fw-eval', from: 'sse', to: 'sse', label: 'Cloud firewall rules', title: 'Cloud firewall rules in priority order', det: 'policy', desc: 'Rules run from the lowest priority number up. All the conditions in a rule must match. The first enabled match decides, and the policy default is Allow.',
            checks: [{ name: 'Rule 100 "Block outbound SSH": TCP, port 22, any destination', ok: false, detail: 'Matches. Action: Block' }, { name: 'Policy default action: Allow', ok: true, detail: 'Not reached' }] },
          blockPage('fw', 'Connection blocked', 'The SSH connection never leaves Microsoft\'s network', 'The edge drops the connection. The cloud firewall is assigned through Conditional Access like the other profiles, so a group of admins could get a profile that allows SSH to known hosts.', { rule: 'Block outbound SSH', action: 'Block' }),
        ];
      }
      const url = v === 'allow' ? 'https://markets.example.com/forums/q3' : v === 'continue' ? 'https://social.example.net/' : 'https://invoice-portal.example.org/login';
      const host = new URL(url).host;
      const start = [
        ...iaSetup(),
        { id: 'ia-open', from: 'user', to: 'pc', label: `Open ${host}`, title: v === 'threat' ? 'User clicks a link in an email' : 'User opens a website', det: 'human', desc: v === 'threat' ? 'The email says an invoice is overdue.' : '' },
        { id: 'ia-req', from: 'pc', to: 'gsaClient', label: `GET ${host}`, title: 'Client acquires the request', det: 'protocol', desc: 'Web traffic on TCP 443, so Default Acquire in the Internet Access profile takes it.', req: { method: 'GET', url } },
        { id: 'ia-tunnel', from: 'gsaClient', to: 'sse', label: 'Tunnel', title: 'Request reaches the edge', det: 'protocol', desc: 'The edge knows who the user is from the tunnel token, so every rule below can depend on identity.' },
      ];
      if (v === 'allow') {
        return [...start,
          { id: 'ia-eval', from: 'sse', to: 'sse', label: 'Finance overrides: Allow', title: 'The Finance profile allows the URL', det: 'policy', desc: 'Profiles run in priority order. The Finance profile has an Allow rule for this URL. URL rules match the path and everything below it. Allow ends evaluation, so the baseline, which blocks Social networking, never sees it.',
            checks: [{ name: 'Profile "Finance overrides" (100): rule Allow https://markets.example.com/forums/', ok: true, detail: 'Match. Evaluation ends' }, { name: 'Baseline profile: Block Social networking', ok: true, detail: 'Not evaluated' }] },
          { id: 'ia-fwd', from: 'sse', to: 'web', label: `GET ${host}`, title: 'Edge forwards the request', det: 'protocol', desc: '', req: { method: 'GET', url } },
          { id: 'ia-page', from: 'web', to: 'pc', label: '200 page', title: 'Page loads', det: 'protocol', desc: 'The traffic log names the profile, policy and rule that allowed it.', res: { status: 200, statusText: 'OK', headers: { 'Content-Type': 'text/html' }, text: '<h1>Q3 market discussion</h1>' } },
        ];
      }
      if (v === 'continue') {
        return [...start,
          { id: 'ia-eval', from: 'sse', to: 'sse', label: 'No match: Continue', title: 'The Finance profile has nothing to say', det: 'policy', desc: 'No rule in the Finance profile matches, and its default action is <b>Continue</b>, so evaluation moves to the next profile in priority order. Allow and Block always end evaluation. Continue only passes on to the same kind of policy in the next profile.',
            checks: [{ name: 'Profile "Finance overrides" (100): no rule matches', ok: true, detail: 'Default action: Continue' }] },
          { id: 'ia-base', from: 'sse', to: 'sse', label: 'Baseline: Block', title: 'The baseline blocks the category', det: 'policy', desc: 'The baseline profile is last and its default can only be Allow or Block, so evaluation always ends here. Its Social networking rule matches.',
            checks: [{ name: 'Baseline profile: rule Block Social networking', ok: false, detail: 'Match. Action: Block' }] },
          blockPage('ia', 'Block page', 'User sees the block page', 'The browser shows the Global Secure Access block page, "It\'s been restricted by your organization", or the custom text the admin set. The request never reaches the site.', { profile: 'Baseline', rule: 'Block Social networking' }),
        ];
      }
      return [...start,
        { id: 'ia-eval', from: 'sse', to: 'sse', label: 'Web filtering: no block', title: 'Web content filtering lets it through', det: 'policy', desc: 'The site is new and sits in an allowed category. Web content filtering runs before threat intelligence, and on its own it would allow this.',
          checks: [{ name: 'Finance overrides and baseline: no web filtering rule blocks it', ok: true }] },
        { id: 'ia-ti', from: 'sse', to: 'sse', label: 'Threat intelligence: Block', title: 'Threat intelligence knows the host', det: 'policy', desc: 'Threat intelligence filtering checks the destination against Microsoft and third-party threat feeds. Its default rule blocks high-severity threats, and the baseline profile carries it so every user gets it.',
          checks: [{ name: `${host} on a threat feed`, ok: false, detail: 'High severity: phishing' }] },
        blockPage('ia', 'Block page', 'Phishing page never loads', 'The user sees the block page instead of a fake sign-in form. The traffic log records the threat type.', { threatType: 'Phishing', severity: 'High' }),
      ];
    },
  });

  /* ---------- Explicit forward proxy ---------- */
  FLOWS.push({
    id: 'gsa-browser-proxy', group: 'gsa', icon: '🖱️', live: false,
    title: 'Browser access without the client',
    subtitle: 'A kiosk or personal device sends its browser through the explicit forward proxy with a PAC file. Entra signs the user in and the same security profiles apply.',
    actors: ['user', 'kiosk', 'sse', 'entra', 'web'],
    layout: { user: [110, 70], kiosk: [110, 330], sse: [480, 330], entra: [480, 70], web: [850, 330] },
    brief: {
      what: 'Some devices can\'t run the Global Secure Access client: kiosks, virtual desktops, Linux machines and personal laptops. The <b>explicit forward proxy</b> brings Internet Access to their browsers. A PAC file sends web traffic to the proxy with HTTP CONNECT. The first time, the proxy redirects the browser to <b>Microsoft Entra</b> sign-in, Conditional Access runs, and the browser comes back to the proxy with an authorization code. After that every request gets the same security profiles as a device with the client. The session follows the access token, 60 to 90 minutes, and supports CAE, so a disabled account or other critical event makes the user sign in again within minutes.',
      prereqs: ['Entra ID P1 and Internet Access licences', 'The PAC file and the TLS inspection root certificate on the device. The proxy terminates TLS for all traffic', `A Conditional Access policy that targets <i>${IA_TARGET}</i> and links the security profile`, 'Smart session management, the default, to tell browsers behind the same IP apart'],
      antiPattern: 'Letting devices that can\'t run the client skip web filtering. Send their browsers through the proxy, so the same identity and the same profiles apply.',
      verify: 'Simulated only. Entra sign-in traffic bypasses the proxy, and Microsoft 365 traffic isn\'t acquired this way.',
    },
    steps: () => [
      { id: 'xp-pac', from: 'kiosk', to: 'kiosk', label: 'PAC file: use the proxy', title: 'Browser reads the PAC file', det: 'protocol', desc: 'The device was set up with the PAC file and the TLS inspection root certificate. The PAC file tells the browser to send web traffic to the Global Secure Access proxy.' },
      { id: 'xp-open', from: 'user', to: 'kiosk', label: 'Open news.example.com', title: 'User opens a website', det: 'human', desc: `${ID.user.name} is at a shared kiosk in the branch office.` },
      { id: 'xp-connect', from: 'kiosk', to: 'sse', label: 'CONNECT news.example.com:443', title: 'Browser asks the proxy for a tunnel', det: 'protocol', desc: 'An ordinary HTTP CONNECT to the explicit forward proxy.', req: { method: 'CONNECT', url: 'news.example.com:443' } },
      { id: 'xp-redirect', from: 'sse', to: 'kiosk', label: 'Redirect to Entra sign-in', title: 'No session yet, so off to Entra', det: 'protocol', desc: 'The proxy doesn\'t know who this is yet, so it redirects the browser to Microsoft Entra sign-in.' },
      { id: 'xp-signin', from: 'kiosk', to: 'entra', label: 'Sign-in', title: 'User signs in to Entra', det: 'human', desc: 'Alex signs in with a passkey on their phone. Entra traffic goes straight to Entra, not through the proxy.' },
      { id: 'xp-ca', from: 'entra', to: 'entra', label: 'Conditional Access', title: 'Conditional Access authorizes the session', det: 'policy', desc: 'The policies that target internet resources with Global Secure Access run here, and one of them links the security profile.',
        checks: [{ name: `Policy target resource: ${IA_TARGET}`, ok: true }, { name: 'Grant: MFA', ok: true, detail: 'Passkey' }, { name: 'Session control: security profile "Finance overrides"', ok: true }] },
      { id: 'xp-code', from: 'entra', to: 'kiosk', label: 'Redirect with auth code', title: 'Back to the proxy with a code', det: 'protocol', desc: 'Entra sends the browser back to the proxy with an authorization code.' },
      { id: 'xp-session', from: 'kiosk', to: 'sse', label: 'Code to the proxy', title: 'Proxy starts the session', det: 'protocol', desc: 'The proxy redeems the code. The session lasts as long as the access token, 60 to 90 minutes. Smart session management keeps this browser\'s session apart from others behind the same IP.' },
      { id: 'xp-policy', from: 'sse', to: 'sse', label: 'Security profiles', title: 'The same profiles as with the client', det: 'policy', desc: 'Web content filtering and threat intelligence run exactly as in the Internet Access tab.',
        checks: [{ name: 'Web content filtering: News is allowed', ok: true }, { name: 'Threat intelligence: no match', ok: true }] },
      { id: 'xp-fwd', from: 'sse', to: 'web', label: 'GET news.example.com', title: 'Proxy forwards the request', det: 'protocol', desc: '', req: { method: 'GET', url: 'https://news.example.com/' } },
      { id: 'xp-page', from: 'web', to: 'kiosk', label: '200 page', title: 'Page loads', det: 'protocol', desc: 'Later requests reuse the session without another sign-in until the token runs out or CAE asks for one.', res: { status: 200, statusText: 'OK', headers: { 'Content-Type': 'text/html' }, text: '<h1>Branch news</h1>' } },
    ],
  });
}
