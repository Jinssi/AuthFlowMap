'use strict';
/* =====================================================================
   CONDITIONAL ACCESS SIMULATOR: inputs, presets and the sample policy set.
   The offline engine is a teaching model of Contoso's policies, not Entra's code.
   Live mode asks Graph's What If API to evaluate the tenant's real policies.
   ===================================================================== */
const CAS_INPUTS = [
  { key: 'subject', label: 'Who', opts: [['user', 'Employee'], ['admin', 'Admin'], ['guest', 'Guest'], ['agent', 'Agent identity']] },
  { key: 'app', label: 'App', opts: [['m365', 'Microsoft 365'], ['finance', 'Finance app'], ['azure', 'Azure management']] },
  { key: 'device', label: 'Device', opts: [['compliant', 'Compliant, Entra joined'], ['hybrid', 'Hybrid joined'], ['registered', 'Registered BYOD'], ['unknown', 'Unknown']], human: true },
  { key: 'platform', label: 'Platform', opts: [['windows', 'Windows'], ['macOS', 'macOS'], ['iOS', 'iOS'], ['android', 'Android'], ['linux', 'Linux']], human: true },
  { key: 'client', label: 'Client', opts: [['browser', 'Browser'], ['desktop', 'Desktop or mobile app'], ['legacy', 'Legacy protocol']], human: true },
  { key: 'location', label: 'Location', opts: [['office', 'Office network'], ['home', 'Home, same country'], ['abroad', 'Abroad'], ['blocked', 'Blocked country']] },
  { key: 'network', label: 'Network path', opts: [['direct', 'Direct to the internet'], ['gsa', 'Through Global Secure Access']], human: true },
  { key: 'method', label: 'User can present', opts: [['none', 'Password only'], ['push', 'Push MFA'], ['passkey', 'Passkey or Windows Hello']], human: true },
  { key: 'flowType', label: 'Sign-in flow', opts: [['normal', 'Normal'], ['devicecode', 'Device code']], human: true },
  { key: 'signInRisk', label: 'Sign-in risk', opts: [['none', 'None'], ['low', 'Low'], ['medium', 'Medium'], ['high', 'High']], human: true },
  { key: 'userRisk', label: 'User risk', opts: [['none', 'None'], ['low', 'Low'], ['medium', 'Medium'], ['high', 'High']], human: true },
  { key: 'authContext', label: 'Sensitive action', opts: [['none', 'No'], ['c1', 'Yes, auth context c1']], human: true },
  { key: 'agentRisk', label: 'Agent risk', opts: [['none', 'None'], ['medium', 'Medium'], ['high', 'High']], agent: true },
];
const CAS_DEFAULT = { subject: 'user', app: 'm365', device: 'unknown', platform: 'windows', client: 'browser', location: 'home', network: 'direct', method: 'push', flowType: 'normal', signInRisk: 'none', userRisk: 'none', authContext: 'none', agentRisk: 'none' };
const CAS_PRESETS = [
  { label: 'Employee on a managed laptop', s: { device: 'compliant', client: 'desktop', location: 'office', network: 'gsa', method: 'passkey' } },
  { label: 'Employee on an unknown home PC', s: { device: 'unknown', client: 'browser', location: 'home', method: 'push' } },
  { label: 'Same PC, Outlook desktop', s: { device: 'unknown', client: 'desktop', location: 'home', method: 'push' } },
  { label: 'Traveller on a hotel VPN', s: { device: 'registered', platform: 'iOS', location: 'abroad', signInRisk: 'medium' } },
  { label: 'Attacker with a stolen password', s: { device: 'unknown', platform: 'linux', location: 'abroad', method: 'none', signInRisk: 'high' } },
  { label: 'Leaked credentials', s: { userRisk: 'high' } },
  { label: 'Admin on a personal Mac', s: { subject: 'admin', app: 'azure', device: 'registered', platform: 'macOS', method: 'push' } },
  { label: 'Device code phishing', s: { device: 'unknown', client: 'desktop', location: 'abroad', flowType: 'devicecode' } },
  { label: 'Approve a payment', s: { app: 'finance', device: 'compliant', location: 'office', network: 'gsa', authContext: 'c1', method: 'push' } },
  { label: 'Finance app off the tunnel', s: { app: 'finance', device: 'compliant', client: 'desktop', location: 'home', network: 'direct', method: 'passkey' } },
  { label: 'Guest partner', s: { subject: 'guest', device: 'unknown', location: 'abroad' } },
  { label: 'Agent with high risk', s: { subject: 'agent', app: 'finance', agentRisk: 'high' } },
];
const RISK = { none: 0, low: 1, medium: 2, high: 3 };
const isHuman = (s) => s.subject !== 'agent';
const managed = (s) => s.device === 'compliant' || s.device === 'hybrid';

/* Each policy returns null when it applies, or the reason it doesn't (Graph What If uses the same idea). */
const CAS_POLICIES = [
  { id: 'CA001', name: 'Require MFA for all users', when: (s) => (isHuman(s) ? null : 'users'), grant: { all: ['mfa'] } },
  { id: 'CA002', name: 'Block legacy authentication', when: (s) => (!isHuman(s) ? 'users' : s.client !== 'legacy' ? 'clientApps' : null), grant: { block: true } },
  { id: 'CA003', name: 'Phishing-resistant MFA for admins', when: (s) => (s.subject !== 'admin' ? 'users' : null), grant: { all: ['phishingResistant'] } },
  { id: 'CA004', name: 'Azure management needs a managed device', when: (s) => (!isHuman(s) ? 'users' : s.app !== 'azure' ? 'application' : null), grant: { any: ['compliantDevice', 'hybridJoined'] } },
  { id: 'CA005', name: 'Finance app needs a compliant device', when: (s) => (!['user', 'admin'].includes(s.subject) ? 'users' : s.app !== 'finance' ? 'application' : null), grant: { all: ['compliantDevice'] } },
  { id: 'CA006', name: 'Unmanaged devices: browser only, restricted session', when: (s) => (!isHuman(s) ? 'users' : s.app !== 'm365' ? 'application' : managed(s) ? 'devices' : null),
    grant: (s) => (s.client === 'desktop' ? { block: true, why: 'Desktop and mobile apps need a managed device' } : { all: [] }), session: ['App-enforced restrictions, no downloads', 'Sign-in frequency 1 hour', 'No persistent browser session'] },
  { id: 'CA007', name: 'Block device code flow', when: (s) => (!isHuman(s) ? 'users' : s.flowType !== 'devicecode' ? 'authenticationFlow' : null), grant: { block: true } },
  { id: 'CA008', name: 'Medium or high sign-in risk requires MFA', when: (s) => (!isHuman(s) ? 'users' : RISK[s.signInRisk] < 2 ? 'signInRisk' : null), grant: { all: ['mfa'] }, session: ['Sign-in frequency every time'] },
  { id: 'CA009', name: 'High user risk requires a password change', when: (s) => (!isHuman(s) ? 'users' : RISK[s.userRisk] < 3 ? 'userRisk' : null), grant: { all: ['mfa', 'passwordChange'] }, session: ['Sign-in frequency every time'] },
  { id: 'CA010', name: 'Block sign-ins from blocked countries', when: (s) => (s.location !== 'blocked' ? 'location' : null), grant: { block: true } },
  { id: 'CA011', name: 'Guests need MFA and terms of use', when: (s) => (s.subject !== 'guest' ? 'users' : null), grant: { all: ['mfa', 'termsOfUse'] } },
  { id: 'CA012', name: 'Sensitive actions need phishing-resistant MFA', when: (s) => (!isHuman(s) ? 'users' : s.authContext !== 'c1' ? 'authenticationContext' : null), grant: { all: ['phishingResistant'] }, session: ['Sign-in frequency every time'] },
  { id: 'CA013', name: 'Token protection for desktop apps on Windows', when: (s) => (!isHuman(s) ? 'users' : s.app !== 'm365' ? 'application' : s.platform !== 'windows' ? 'devicePlatform' : s.client !== 'desktop' ? 'clientApps' : null), grant: { all: ['boundSession'] }, session: ['Token protection for sign-in sessions'] },
  { id: 'CA014', name: 'Agents: block high-risk agent identities', when: (s) => (isHuman(s) ? 'users' : RISK[s.agentRisk] < 3 ? 'servicePrincipalRisk' : null), grant: { block: true }, preview: true },
  { id: 'CA015', name: 'Finance app only through the compliant network', when: (s) => (!['user', 'admin'].includes(s.subject) ? 'users' : s.app !== 'finance' ? 'application' : s.network === 'gsa' ? 'compliantNetwork' : null),
    grant: { block: true, why: 'Not in All Compliant Network locations' } },
];
const CAS_CONTROLS = {
  mfa: { label: 'MFA', ok: (s) => s.method !== 'none', prompt: (s) => !(managed(s) && s.method === 'passkey') },
  phishingResistant: { label: 'Phishing-resistant MFA', ok: (s) => s.method === 'passkey', prompt: (s) => !(managed(s) && s.method === 'passkey') },
  compliantDevice: { label: 'Compliant device', ok: (s) => s.device === 'compliant' },
  hybridJoined: { label: 'Hybrid joined device', ok: (s) => s.device === 'hybrid' },
  passwordChange: { label: 'Secure password change', ok: (s) => s.method !== 'none', prompt: () => true },
  termsOfUse: { label: 'Accept terms of use', ok: () => true, prompt: () => true },
  boundSession: { label: 'Session bound to the device', ok: (s) => s.device !== 'unknown' },
};
const CAS_REASONS = {
  users: 'User or identity not targeted', application: 'App not targeted', devices: 'Device excluded (already managed)', clientApps: 'Client app not targeted',
  authenticationFlow: 'Not a device code flow', signInRisk: 'Sign-in risk below threshold', userRisk: 'User risk below threshold', location: 'Location not targeted',
  authenticationContext: 'No authentication context requested', devicePlatform: 'Platform not targeted', servicePrincipalRisk: 'Agent risk below threshold',
  compliantNetwork: 'Came through the compliant network, which the policy excludes',
};

FLOWS.push({
  id: 'ca-sim', group: 'access', icon: '🚦', live: true, kind: 'simulator',
  title: 'Conditional Access simulator',
  subtitle: 'Change the device, location, risk or app and watch the decision change for the same user.',
  actors: ['user', 'pc', 'browser', 'entra', 'intune', 'risk'],
  brief: {
    what: 'Every sign-in is a question: who, to which app, from what device, where, how risky, and with which method. Conditional Access answers it. A policy can block, allow after grant controls such as MFA or a compliant device, or allow with session limits. Blocks always win, and every policy that applies has to be satisfied. Change one switch and the same user on the same app gets a different answer. <b>Network path</b> shows the compliant network check: the finance app only accepts sign-ins that come through Contoso\'s own Global Secure Access, wherever the user is.',
    prereqs: ['Entra ID P1 for Conditional Access, P2 for risk-based conditions', 'Devices registered in Entra and managed by Intune for device conditions', 'Named locations for the office network', 'Global Secure Access with signaling for Conditional Access turned on, for the compliant network policy'],
    antiPattern: 'One giant policy with dozens of exclusions, or policies left in report-only forever. Keep policies small, named after what they do, and always exclude two break-glass accounts.',
    verify: 'The offline engine models a sample Contoso policy set. In Live mode the same switches go to Graph\'s What If API, and you see what your tenant\'s real policies would do. What If has no input for the network path, so the compliant network only shows in the offline model.',
  },
  steps: () => [],
});
