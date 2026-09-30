'use strict';
/* =====================================================================
   REFERENCE TABLES: authentication methods, devices, Conditional Access.
   ===================================================================== */
const REF_ACCESS_A = [
  {
    id: 'methods', title: 'Authentication methods by strength',
    intro: 'Phishing-resistant means the method checks which site it\'s talking to, so an attacker-in-the-middle page gets nothing it can replay. See the <a href="#flow/aitm">session theft tab</a>.',
    cols: ['Method', 'Factor', 'Phishing-resistant?', 'Notes'],
    rows: [
      ['Password', 'Something you know', 'No', 'Reused, sprayed, leaked. The weakest link in every other row'],
      ['SMS or voice call', 'Second factor', 'No', 'SIM swapping and relay. Keep it for recovery at most'],
      ['Authenticator push with number matching', 'Second factor', 'No', 'Stops push fatigue, but a proxy can still relay the session'],
      ['Authenticator or hardware OTP code', 'Second factor', 'No', 'The user can type the code into a phishing page'],
      ['Passkey, FIDO2 key or passkey in Authenticator', 'Passwordless MFA', '<b>Yes</b>', 'Bound to the real origin. The browser refuses to use it on a fake site'],
      ['Windows Hello for Business', 'Passwordless MFA', '<b>Yes</b>', 'Key in the TPM, and it also gives the device its PRT'],
      ['Platform SSO on macOS', 'Passwordless MFA', '<b>Yes</b>', 'Secure Enclave key, the macOS counterpart of Windows Hello'],
      ['Certificate-based authentication', 'MFA with a smart card or derived credential', '<b>Yes</b>', 'Common in government and regulated industries'],
      ['Temporary Access Pass', 'Time-limited passcode', 'No', 'For onboarding and recovery, used to register a passkey'],
    ],
  },
  {
    id: 'devices', title: 'Device states',
    intro: 'What Entra knows about the device decides what Conditional Access can demand. See the <a href="#flow/device-sso">device identity tab</a>.',
    cols: ['State', 'What it means', 'Gets a PRT?', 'Conditional Access can require'],
    rows: [
      ['Unknown', 'Entra has never seen the device', 'No', 'Nothing about the device. Only block, or allow with browser restrictions'],
      ['Entra registered', 'A personal device with a work account added', 'Yes, for that account', 'Device filters, and compliance when enrolled in Intune'],
      ['Entra joined', 'A company device signed in with the work account', 'Yes', 'Compliant device, device filters, token protection'],
      ['Hybrid joined', 'Joined to on-premises AD and registered in Entra', 'Yes', '"Hybrid joined device", compliance'],
      ['Compliant', 'Intune marked it healthy: encryption, patches, Defender', 'Depends on the join type', '"Require compliant device"'],
      ['App protection', 'An unmanaged phone with a managed app, such as Outlook with Intune app policies', 'Through the broker app', '"Require app protection policy"'],
    ],
  },
  {
    id: 'ca', title: 'Conditional Access building blocks',
    intro: 'Signals go in, a decision comes out, and some of it shows up in the token. See the <a href="#flow/ca-sim">simulator</a>.',
    cols: ['Part', 'Examples', 'Shows up in the token as'],
    rows: [
      ['Assignment: who', 'Users, groups, roles, guests, workload identities, agent identities', '<code>oid</code>, <code>idtyp</code>, <code>xms_*</code>'],
      ['Assignment: what', 'Cloud apps, user actions such as registering security info, authentication contexts', '<code>aud</code>, <code>acrs</code>'],
      ['Condition: device', 'Platform, device filters, join type, compliance', '<code>deviceid</code>'],
      ['Condition: network', 'Named locations, countries, compliant network through Global Secure Access', '<code>ipaddr</code>'],
      ['Condition: risk', 'Sign-in risk, user risk, insider risk, agent and workload risk', 'Nothing. Risk stays in Entra'],
      ['Condition: client and flow', 'Browser, desktop apps, legacy protocols, device code flow, authentication transfer', '<code>appid</code>, <code>amr</code>'],
      ['Grant: block', 'Block access', 'No token at all. AADSTS53003'],
      ['Grant: require', 'MFA, authentication strength, compliant device, hybrid joined, app protection, password change, terms of use', '<code>amr</code>, <code>acrs</code>, <code>deviceid</code>'],
      ['Session', 'Sign-in frequency, persistent browser, app-enforced restrictions, Defender for Cloud Apps, token protection, CAE strict enforcement', 'Token lifetime, <code>xms_cc</code>'],
    ],
  },
];

const REF_ACCESS_B = [
  {
    id: 'hybrid', title: 'Hybrid identity',
    intro: 'Most customers still have Active Directory. How identities and passwords get to Entra decides what keeps working when something breaks.',
    cols: ['Option', 'How it works', 'Good for', 'Watch for'],
    rows: [
      ['Entra Connect Sync or Cloud Sync', 'Synchronises users and groups from AD to Entra', 'Every hybrid tenant', 'Cloud Sync is lighter and is where new features land'],
      ['Password hash sync', 'A hash of the AD password hash goes to Entra. Sign-in happens in the cloud', 'The default. Enables leaked-credential detection', 'Sign-in keeps working even when on-premises is down'],
      ['Pass-through authentication', 'Entra hands the password to agents on-premises for checking', 'Rules that forbid password hashes in the cloud', 'On-premises outage means no sign-in. Add PHS as a backup'],
      ['Federation with AD FS', 'Entra redirects to AD FS for sign-in', 'Legacy only', 'Extra infrastructure and a golden SAML risk. Most customers migrate to PHS or staged rollout'],
      ['Cloud Kerberos trust', 'Entra issues partial Kerberos tickets for on-premises resources', 'Windows Hello for Business to on-premises file shares', 'Replaces key and certificate trust for WHfB'],
      ['App Proxy or Private Access', 'Publishes on-premises web apps through Entra, with Kerberos delegation', 'Old intranet apps behind Conditional Access', 'Private Access is part of Global Secure Access'],
    ],
  },
  {
    id: 'external', title: 'External identities',
    cols: ['Scenario', 'Feature', 'Notes'],
    rows: [
      ['Partner users working in your tenant', 'B2B collaboration, guest users', 'The guest signs in with their home account. Your Conditional Access applies'],
      ['Trusting the partner\'s MFA and devices', 'Cross-tenant access settings, inbound trust', 'Accept their MFA and compliant-device claims so guests aren\'t prompted twice'],
      ['Teams shared channels between organisations', 'B2B direct connect', 'No guest object in your directory'],
      ['Several tenants inside one company', 'Multitenant organisation, cross-tenant sync', 'Users show up as members, not guests'],
      ['Customers and consumers', 'Entra External ID', 'Separate tenant for customer identities, social sign-in, custom branding'],
      ['Other identity providers', 'SAML or WS-Fed IdP federation, Google, email one-time passcode', 'For partners without Entra'],
    ],
  },
  {
    id: 'governance', title: 'Governance and lifecycle',
    intro: 'Getting access right on day one is easy. Taking it away on the right day is where most tenants fail.',
    cols: ['Area', 'Feature', 'What it does'],
    rows: [
      ['Joiner, mover, leaver', 'Lifecycle workflows, HR-driven provisioning', 'Creates, updates and disables accounts from HR data'],
      ['Admin roles', 'Privileged Identity Management', 'Just-in-time, time-limited admin roles with approval and phishing-resistant MFA'],
      ['Access that piles up', 'Access reviews', 'Owners or managers confirm who still needs access, and the rest get removed'],
      ['Self-service access', 'Entitlement management, access packages', 'Bundles of groups, apps and sites with approval and expiry'],
      ['Apps and workload identities', 'Workload identity Conditional Access and ID Protection, app instance lock', 'Limits where service principals can sign in from, and flags risky ones'],
      ['Agents', 'Agent ID sponsors, agent registry, Conditional Access and ID Protection for agents', 'Every agent has a human owner, can be switched off on its own and is governed like other identities. Parts are in preview'],
      ['Break-glass accounts', 'Two emergency access accounts', 'Excluded from Conditional Access, phishing-resistant credentials, and alerts on every sign-in'],
    ],
  },
];
const consentIdx = REFERENCE.findIndex((s) => s.id === 'consent');
REFERENCE.splice(consentIdx + 1, 0, ...REF_ACCESS_A, ...REF_ACCESS_B);
