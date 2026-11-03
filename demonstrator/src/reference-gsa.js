'use strict';
/* =====================================================================
   REFERENCE TABLES: Global Secure Access and Zero Trust.
   Sources: the Global Secure Access offering blog (Nov 2026), "Secure AI, web, and private apps with
   Zero Trust" and the Learn pages listed under Documentation links.
   ===================================================================== */
{
  const tab = (id, label) => `<a href="#flow/${id}">${label}</a>`;
  const REF_GSA = [
    {
      id: 'gsa', title: 'Global Secure Access at a glance',
      intro: `Microsoft Entra Global Secure Access is Microsoft's Security Service Edge: Microsoft Entra Private Access and Microsoft Entra Internet Access, sold together since 2 November 2026 and still available on their own. Entra Suite includes it, and Microsoft 365 E7 includes Entra Suite. It uses the users, groups, apps and Conditional Access policies already in Entra. See the ${tab('gsa-private-access', 'Private Access tab')} first.`,
      cols: ['Part', 'What it does', 'Tab'],
      rows: [
        ['Global Secure Access client', 'Runs on Windows, macOS, iOS and Android. Tunnels the traffic its forwarding profiles cover to the nearest edge, with an Entra token per tunnel', tab('gsa-private-access', 'Private Access')],
        ['Traffic forwarding profiles', 'Checked in order: Microsoft traffic, then Private Access, then Internet Access. Entra sign-in traffic always has its own profile', tab('gsa-compliant-network', 'Compliant network')],
        ['Quick Access and per-app access', 'Quick Access publishes a broad set of private FQDNs and IP ranges as one app. Per-app access gives a server its own enterprise app, users and Conditional Access policy', tab('gsa-private-access', 'Private Access')],
        ['Private network connector', 'Next to the app. Outbound connections only, so no inbound firewall ports. Connector groups give high availability and session affinity', tab('gsa-private-access', 'Private Access')],
        ['Security profiles', 'Linked to users and groups by a Conditional Access session control, and run in priority order. The baseline profile applies to everyone and runs last. A Continue default action passes to the next profile', tab('gsa-internet-access', 'Internet Access')],
        ['Controls inside a profile', 'TLS inspection, web content filtering, threat intelligence, file type, DLP, third-party, in that order', tab('gsa-internet-access', 'Internet Access')],
        ['Cloud firewall', 'Allow and Block rules on destination, port and protocol for TCP and UDP beyond the web. Needs Custom Acquire for ports other than 80 and 443', tab('gsa-internet-access', 'Internet Access')],
        ['TLS inspection', 'Decrypts web traffic so content can be checked. A Microsoft-managed certificate means no PKI of your own', tab('gsa-ai-data', 'AI and data')],
        ['Network content filtering', 'Sends uploads and text to Microsoft Purview and enforces its DLP verdict, for people and for agents acting for them', tab('gsa-ai-data', 'AI and data')],
        ['Prompt injection protection', 'The AI gateway blocks jailbreak and injection prompts to AI apps before they reach the model', tab('gsa-ai-data', 'AI and data')],
        ['Custom headers', 'Adds headers the user can\'t see to traffic for chosen apps, for example to keep a SaaS app to the company workspace', tab('gsa-ai-data', 'AI and data')],
        ['Compliant network check', 'A Conditional Access location that means "came through our own Global Secure Access". Blocks token replay on the authentication and data planes', tab('gsa-compliant-network', 'Compliant network')],
        ['Source IP restoration', 'Passes the user\'s real public IP to Entra, so location policies, risk detection and logs stay accurate', tab('gsa-compliant-network', 'Compliant network')],
        ['Universal CAE', 'Reevaluates access at the edge when a user or device changes state. The destination app doesn\'t need CAE support', tab('gsa-universal-cae', 'Universal CAE')],
        ['Explicit forward proxy', 'A PAC file sends a browser to Global Secure Access on devices that can\'t run the client', tab('gsa-browser-proxy', 'Browser proxy')],
        ['Network controls for agents', 'Agentic Acquire for local agents, the client on Windows 365 for Agents Cloud PCs, and a Power Platform setting for Copilot Studio agents. MCP calls to remote servers are logged', tab('gsa-agents', 'Agents')],
      ],
    },
    {
      id: 'zerotrust', title: 'Zero Trust across the tabs',
      intro: 'Zero Trust means checking every connection against its full context, identity, risk, device, app and data, location and network, and enforcing the decision continuously, not only at sign-in. The three principles are verify explicitly, use least privilege and assume breach. This table maps them to the tabs that show them.',
      cols: ['Principle or signal', 'What it looks like here', 'Tabs'],
      rows: [
        ['Verify explicitly: identity', 'Entra authenticates the user or workload and signs every token. Resources check the signature, issuer and audience', `${tab('auth-code-pkce', 'Auth code + PKCE')}, ${tab('client-credentials', 'Client credentials')}`],
        ['Verify explicitly: authentication strength', 'Phishing-resistant MFA and step-up for sensitive actions', `${tab('aitm', 'Session theft')}, ${tab('step-up', 'Step-up MFA')}`],
        ['Verify explicitly: device', 'Device identity and Intune compliance as Conditional Access grants, for SaaS and private apps alike', `${tab('device-sso', 'Device identity')}, ${tab('gsa-private-access', 'Private Access')}`],
        ['Verify explicitly: risk', 'Sign-in and user risk from ID Protection drive Conditional Access', tab('id-protection', 'Identity Protection')],
        ['Verify explicitly: network', 'The compliant network check instead of trusted IP ranges', tab('gsa-compliant-network', 'Compliant network')],
        ['Verify explicitly: data', 'Purview labels and DLP decide what may leave, and Microsoft 365 permissions decide what an agent may read', `${tab('gsa-ai-data', 'AI and data')}, ${tab('iq-oversharing', 'Oversharing')}`],
        ['Least privilege: apps and tokens', 'One audience per token, scopes and app roles, OBO for each hop', `${tab('obo', 'On-behalf-of')}, ${tab('mcp-obo', 'MCP OBO')}`],
        ['Least privilege: network', 'Per-app access to one host and port instead of a VPN onto the whole network. Agents limited to approved destinations', `${tab('gsa-private-access', 'Private Access')}, ${tab('gsa-agents', 'Agents')}`],
        ['Least privilege: agents', 'Agent identities from a blueprint, delegated permissions and human step-up for risky actions', `${tab('agent-obo', 'Agent OBO')}, ${tab('step-up', 'Step-up MFA')}`],
        ['Assume breach: stolen tokens', 'Token protection, compliant network and CAE make stolen tokens useless elsewhere', `${tab('aitm', 'Session theft')}, ${tab('gsa-compliant-network', 'Compliant network')}, ${tab('refresh-cae', 'Refresh and CAE')}`],
        ['Assume breach: continuous evaluation', 'Access ends when the user or device changes state, even for apps that never heard of CAE', tab('gsa-universal-cae', 'Universal CAE')],
        ['Assume breach: malicious destinations and prompts', 'Threat intelligence, file filtering and prompt policies at the edge', `${tab('gsa-internet-access', 'Internet Access')}, ${tab('gsa-ai-data', 'AI and data')}`],
        ['Assume breach: visibility', 'Sign-in logs for every token, and traffic logs that name the profile, rule and MCP call', `${tab('gsa-agents', 'Agents')}, ${tab('gsa-internet-access', 'Internet Access')}`],
      ],
    },
  ];
  const at = REFERENCE.findIndex((s) => s.id === 'governance');
  REFERENCE.splice(at < 0 ? REFERENCE.length : at + 1, 0, ...REF_GSA);
}
