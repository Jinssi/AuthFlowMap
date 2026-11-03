'use strict';
/* =====================================================================
   LEARNING AIDS: glossary and toggletips, threats, the suggested
   learning order, copy-as-command and run export.
   ===================================================================== */
const GLOSSARY = [
  { term: 'Access token', re: /\baccess tokens?\b/i, def: 'A signed token an app sends to one API to call it. The API it is for is named in aud, and scp or roles say what the caller may do.' },
  { term: 'ID token', re: /\bID tokens?\b/, def: 'Tells the app who signed in. Only the app reads it. Never send it to an API.' },
  { term: 'Refresh token', re: /\brefresh tokens?\b/i, def: 'A long-lived, opaque token the app trades with Entra for new access tokens, so the user doesn\'t sign in again. Only Entra can read it.' },
  { term: 'Authorization code', re: /\b(authorization|auth) codes?\b/i, def: 'A short-lived, one-time code Entra hands to the app after sign-in. The app swaps it for tokens at the /token endpoint.' },
  { term: 'PKCE', re: /\bPKCE\b/, def: 'Proof Key for Code Exchange. The app sends a hash of a random secret when sign-in starts and the secret itself when it redeems the code, so a stolen code is useless.' },
  { term: 'Redirect URI', re: /\bredirect URIs?\b/i, def: 'The exact address Entra sends the user back to after sign-in. It has to be registered on the app, character for character.' },
  { term: 'Scope', re: /\bscopes?\b/i, def: 'A named permission the app asks for, such as User.Read. Delegated scopes end up in the scp claim.' },
  { term: 'Audience', re: /\baudiences?\b|\baud\b/i, def: 'The aud claim: which API a token is for. An API must reject tokens with any other audience.' },
  { term: 'Claim', re: /\bclaims?\b/i, def: 'One named value inside a token, such as oid for the object ID or exp for the expiry time.' },
  { term: 'JWT', re: /\bJWTs?\b/, def: 'JSON Web Token: a header, a payload of claims and a signature, each base64url-encoded and joined with dots.' },
  { term: 'Consent', re: /\bconsent\b/i, def: 'Approval for an app to use a permission, given by the user or once for everyone by an admin.' },
  { term: 'Delegated permission', re: /\bdelegated\b/i, def: 'The app acts for a signed-in user and can never do more than that user can. Shows up as scp.' },
  { term: 'Application permission', re: /\b(application|app-only) permissions?\b|\bapp roles?\b/i, def: 'The app acts as itself with no user, for example a nightly job. Shows up as roles, and needs admin consent.' },
  { term: 'Client credentials', re: /\bclient credentials\b/i, def: 'The OAuth grant where an app gets a token as itself, proving who it is with a certificate, a federated credential or a secret.' },
  { term: 'On-behalf-of', re: /\bon-behalf-of\b|\bOBO\b/i, def: 'An API swaps the user token it received for a new token to call the next API, still for the same user.' },
  { term: 'Tenant', re: /\btenants?\b/i, def: 'One organisation\'s instance of Microsoft Entra ID, with its own users, apps and policies. Its ID is the tid claim.' },
  { term: 'Service principal', re: /\bservice principals?\b/i, def: 'The local copy of an app inside a tenant. Permissions, consent and sign-in logs attach to it.' },
  { term: 'Managed identity', re: /\bmanaged identit(y|ies)\b/i, def: 'An identity Azure creates and rotates for a resource, so the code holds no secret at all.' },
  { term: 'Federated credential', re: /\bfederated (identity )?credentials?\b/i, def: 'Trust in another identity provider\'s token, such as GitHub\'s, instead of a secret. Pin the issuer and subject tightly.' },
  { term: 'Conditional Access', re: /\bConditional Access\b/, def: 'Entra\'s policy engine. It looks at who, what app, which device and how risky, then allows, blocks or asks for more, such as MFA.' },
  { term: 'MFA', re: /\bMFA\b/, def: 'Multifactor authentication: a second proof besides the password. Passkeys and other phishing-resistant methods are the strongest.' },
  { term: 'CAE', re: /\bCAE\b|\bcontinuous access evaluation\b/i, def: 'Continuous access evaluation. Supporting APIs reject a token straight away when the user is disabled, moves network or changes password.' },
  { term: 'Agent identity blueprint', re: /\bblueprints?\b/i, def: 'The template app that holds the credential and creates agent identities. It requests tokens on their behalf.' },
  { term: 'Agent identity', re: /\bagent identit(y|ies)\b/i, def: 'A separate identity per AI agent instance, created from a blueprint, so each agent shows up and can be switched off on its own.' },
  { term: 'MCP', re: /\bMCP\b/, def: 'Model Context Protocol: a standard way for an AI host to offer tools to a model. Remote MCP servers are protected with OAuth.' },
  { term: 'Zero Trust', re: /\bZero Trust\b/, def: 'A security model that checks every request against identity, device, risk, data and network, grants the least access needed and assumes a breach has already happened.' },
  { term: 'Global Secure Access', re: /\bGlobal Secure Access\b/, def: 'Microsoft\'s Security Service Edge: Entra Private Access and Entra Internet Access, with a client that tunnels traffic to Microsoft\'s edge, where Entra policy is enforced.' },
  { term: 'Security Service Edge', re: /\bSecurity Service Edge\b|\bSSE\b/, def: 'Network security delivered from the cloud: secure web gateway, zero trust network access and data protection, close to the user instead of in the datacenter.' },
  { term: 'Traffic forwarding profile', re: /\btraffic forwarding profiles?\b/i, def: 'Tells the Global Secure Access client which traffic to tunnel: Microsoft traffic, Private Access or Internet Access.' },
  { term: 'Security profile', re: /\bsecurity profiles?\b/i, def: 'A bundle of Global Secure Access policies, such as web filtering and threat intelligence, linked to users through a Conditional Access session control.' },
  { term: 'Private network connector', re: /\bprivate network connectors?\b/i, def: 'An agent next to a private app that connects outbound to Global Secure Access and opens connections to the app, so no inbound port is needed.' },
  { term: 'Compliant network', re: /\bcompliant network\b/i, def: 'A Conditional Access location meaning the request came through the tenant\'s own Global Secure Access, not a list of IP ranges.' },
  { term: 'Universal CAE', re: /\bUniversal CAE\b/, def: 'Continuous access evaluation enforced by Global Secure Access, so access to any app ends when the user or device changes state.' },
  { term: 'TLS inspection', re: /\bTLS inspection\b/i, def: 'The edge decrypts HTTPS with a certificate the devices trust, so it can check content, not just host names.' },
];
const GLOSS_MAX = 8;

/* Toggletips on the first use of each glossary term, inside elements marked data-gloss. */
function glossarize(root) {
  if (!root) return;
  const used = new Set(); let count = 0;
  for (const el of $$('[data-gloss]', root)) {
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, { acceptNode: (t) => (t.parentElement.closest('code,a,button,label,.gloss') ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT) });
    const nodes = []; while (walker.nextNode()) nodes.push(walker.currentNode);
    for (let node of nodes) {
      while (node && count < GLOSS_MAX) {
        let best = null;
        for (const g of GLOSSARY) {
          if (used.has(g.term)) continue;
          const m = g.re.exec(node.data);
          if (m && (!best || m.index < best.m.index)) best = { g, m };
        }
        if (!best) break;
        used.add(best.g.term); count++;
        const hit = node.splitText(best.m.index), rest = hit.splitText(best.m[0].length);
        const b = document.createElement('button');
        b.type = 'button'; b.className = 'gloss'; b.textContent = best.m[0]; b.dataset.term = best.g.term;
        b.setAttribute('aria-expanded', 'false'); b.setAttribute('aria-controls', 'glossTip');
        hit.replaceWith(b);
        node = rest;
      }
    }
  }
}
function glossTipEl() {
  let t = $('#glossTip');
  if (!t) { t = document.createElement('div'); t.id = 'glossTip'; t.className = 'gloss-tip'; t.hidden = true; document.body.appendChild(t); }
  return t;
}
function closeGlossTip(focusBack) {
  const t = $('#glossTip'); if (!t || t.hidden) return;
  t.hidden = true;
  const b = $('.gloss[aria-expanded="true"]');
  if (b) { b.setAttribute('aria-expanded', 'false'); if (focusBack) b.focus(); }
}
function openGlossTip(b) {
  const g = GLOSSARY.find((x) => x.term === b.dataset.term); if (!g) return;
  closeGlossTip(false);
  const t = glossTipEl();
  t.innerHTML = `<b>${esc(g.term)}.</b> ${esc(g.def)}`;
  t.hidden = false; b.setAttribute('aria-expanded', 'true');
  const r = b.getBoundingClientRect(), w = t.offsetWidth, h = t.offsetHeight;
  const left = Math.max(8, Math.min(r.left, window.innerWidth - w - 8));
  const top = r.bottom + 6 + h > window.innerHeight - 8 ? Math.max(8, r.top - h - 6) : r.bottom + 6;
  t.style.left = `${left}px`; t.style.top = `${top}px`;
  announce(`${g.term}. ${g.def}`);
}
function initGlossary() {
  document.addEventListener('click', (e) => {
    const b = e.target.closest('.gloss');
    if (b) { if (b.getAttribute('aria-expanded') === 'true') closeGlossTip(false); else openGlossTip(b); return; }
    if (!e.target.closest('#glossTip')) closeGlossTip(false);
  });
  document.addEventListener('keydown', (e) => { const tip = $('#glossTip'); if (e.key === 'Escape' && tip && !tip.hidden) { e.stopPropagation(); closeGlossTip(true); } }, true);
  $('#main').addEventListener('scroll', () => closeGlossTip(false), { passive: true });
  window.addEventListener('resize', () => closeGlossTip(false));
  window.addEventListener('hashchange', () => closeGlossTip(false));
}

/* ---------- threats ---------- */
const RFC9700 = (sec) => ({ label: `RFC 9700 §${sec}`, url: `https://www.rfc-editor.org/rfc/rfc9700#section-${sec}` });
const THREATS = [
  { name: 'Authorization code interception or injection', stop: 'PKCE binds the code to the app that started the sign-in. A code without its verifier is rejected.', mitre: ['T1528'], std: [RFC9700('4.5')], flows: ['auth-code-pkce', 'web-app'] },
  { name: 'Redirect URI manipulation', stop: 'Entra only sends codes to redirect URIs registered on the app, matched exactly.', mitre: ['T1528'], std: [RFC9700('4.1')], flows: ['auth-code-pkce', 'web-app'] },
  { name: 'Cross-site request forgery on the redirect', stop: 'The state value and PKCE tie the response to the browser session that started it.', mitre: [], std: [RFC9700('4.7')], flows: ['auth-code-pkce', 'web-app'] },
  { name: 'Token replay against the wrong API', stop: 'Each API checks aud, so a token for one API is useless at another. OBO mints a new token per hop.', mitre: ['T1550.001'], std: [RFC9700('4.10.2')], flows: ['obo', 'agent-obo', 'mcp-auth', 'mcp-obo', 'multi-agent'] },
  { name: 'MCP token passthrough (confused deputy)', stop: 'The MCP server accepts only tokens issued for itself and uses OBO, never the caller\'s token, for the next hop.', mitre: ['T1550.001'], std: [{ label: 'MCP security best practices', url: 'https://modelcontextprotocol.io/specification/draft/basic/security_best_practices' }, RFC9700('4.9')], flows: ['mcp-auth', 'mcp-obo', 'multi-agent'] },
  { name: 'Stolen access token reuse', stop: 'Short lifetimes, CAE revocation on critical events and token protection that binds tokens to the device.', mitre: ['T1550.001'], std: [RFC9700('4.10')], flows: ['refresh-cae', 'aitm', 'device-sso'] },
  { name: 'Refresh token theft', stop: 'Refresh tokens rotate, SPA ones expire in 24 hours, Conditional Access runs on every use and CAE revokes them.', mitre: ['T1528'], std: [RFC9700('4.14')], flows: ['refresh-cae', 'device-sso'] },
  { name: 'Leaked client secret', stop: 'A managed identity, a federated credential or a certificate, so there is no secret to leak.', mitre: ['T1552.001'], std: [RFC9700('2.5')], flows: ['client-credentials', 'managed-identity', 'wif', 'web-app', 'agent-autonomous'] },
  { name: 'Over-broad federated credential', stop: 'Pin the issuer, subject and audience, so only one repo, branch or service account can sign in.', mitre: ['T1078.004'], std: [{ label: 'RFC 7523', url: 'https://www.rfc-editor.org/rfc/rfc7523' }], flows: ['wif'] },
  { name: 'Adversary-in-the-middle phishing', stop: 'Phishing-resistant MFA such as passkeys, which are bound to the real sign-in domain, plus token protection.', mitre: ['T1557', 'T1539'], std: [], flows: ['aitm'] },
  { name: 'Device code phishing', stop: 'Block the device code flow with a Conditional Access authentication flows policy wherever it isn\'t needed.', mitre: ['T1566.002', 'T1528'], std: [{ label: 'RFC 8628 §5.4', url: 'https://www.rfc-editor.org/rfc/rfc8628#section-5.4' }], flows: ['device-code'] },
  { name: 'Password spray and risky sign-ins', stop: 'MFA, Identity Protection risk policies and step-up for sensitive actions.', mitre: ['T1110.003'], std: [], flows: ['id-protection', 'step-up'] },
  { name: 'Prompt injection stealing credentials', stop: 'The host holds every token and secret. The model only chooses tools, so there is nothing in its context to steal.', mitre: ['AML.T0051'], std: [{ label: 'OWASP LLM01', url: 'https://genai.owasp.org/llmrisk/llm01-prompt-injection/' }], flows: ['agent-autonomous', 'agent-obo', 'agent-user', 'multi-agent', 'workiq-mcp'] },
  { name: 'Overshared data surfacing through an agent', stop: 'Answers are trimmed with the user\'s own permissions and labels, so an agent sees only what the user may see.', mitre: ['AML.T0057'], std: [{ label: 'OWASP LLM02', url: 'https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/' }], flows: ['iq-oversharing', 'foundry-iq', 'workiq-mcp', 'foundry-workiq'] },
  { name: 'Lateral movement from a VPN-connected device', stop: 'Per-app Private Access reaches one host and port per app, each behind its own Conditional Access policy, through connectors that accept no inbound connections.', mitre: ['T1021', 'T1133'], std: [], flows: ['gsa-private-access'] },
  { name: 'Stolen token replayed from outside', stop: 'The compliant network check refuses the refresh token at Entra, and CAE resources such as Graph reject the access token.', mitre: ['T1550.001', 'T1528'], std: [RFC9700('4.10')], flows: ['gsa-compliant-network'] },
  { name: 'Access that outlives a compromised device or account', stop: 'Universal CAE reevaluates at the Global Secure Access edge on device and risk events and closes the tunnels if Conditional Access fails.', mitre: ['T1078'], std: [], flows: ['gsa-universal-cae', 'gsa-compliant-network'] },
  { name: 'Phishing and malicious destinations', stop: 'Threat intelligence filtering and web content filtering at the edge, for people, kiosks and agents.', mitre: ['T1566.002', 'T1189'], std: [], flows: ['gsa-internet-access', 'gsa-browser-proxy', 'gsa-agents'] },
  { name: 'Sensitive data uploaded to AI or web apps', stop: 'TLS inspection and network content filtering with Purview block labelled or sensitive content on its way out.', mitre: ['T1567'], std: [{ label: 'OWASP LLM02', url: 'https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/' }], flows: ['gsa-ai-data', 'gsa-agents'] },
  { name: 'Jailbreak and prompt injection against AI apps and agents', stop: 'Prompt policies in the AI gateway block adversarial prompts, and agents are kept to approved destinations, so an injected instruction can\'t send data out.', mitre: ['AML.T0051', 'AML.T0054'], std: [{ label: 'OWASP LLM01', url: 'https://genai.owasp.org/llmrisk/llm01-prompt-injection/' }], flows: ['gsa-ai-data', 'gsa-agents'] },
];
const mitreUrl = (id) => (id.startsWith('AML.') ? `https://atlas.mitre.org/techniques/${id}` : `https://attack.mitre.org/techniques/${id.replace('.', '/')}/`);
const extLink = (url, label, title) => `<a href="${esc(url)}" target="_blank" rel="noopener"${title ? ` title="${esc(title)}"` : ''}>${esc(label)}</a>`;
const threatRefs = (t) => [...t.mitre.map((m) => extLink(mitreUrl(m), m, m.startsWith('AML.') ? 'MITRE ATLAS technique' : 'MITRE ATT&CK technique')), ...t.std.map((s) => extLink(s.url, s.label))].join(' · ');
function threatsHtml(flowId) {
  const list = THREATS.filter((t) => t.flows.includes(flowId));
  if (!list.length) return '';
  return `<details class="threats"><summary>Threats this flow stops (${list.length})</summary><ul class="tight">${list.map((t) => `<li><b>${esc(t.name)}.</b> ${esc(t.stop)} <span class="soft threat-refs">${threatRefs(t)}</span></li>`).join('')}</ul></details>`;
}

/* ---------- glossary and threats in the reference page ---------- */
REFERENCE.splice(Math.max(0, REFERENCE.findIndex((s) => s.id === 'errors')), 0, {
  id: 'threats', title: 'Threats and what stops them',
  intro: 'Each row names the attack, the control in these flows that stops it, the MITRE technique and the standard that describes it. The flow briefings list the threats each flow defends against.',
  cols: ['Threat', 'What stops it', 'MITRE', 'Standard', 'Tab'],
  rows: THREATS.map((t) => [esc(t.name), esc(t.stop), t.mitre.map((m) => extLink(mitreUrl(m), m)).join(', ') || NA, t.std.map((s) => extLink(s.url, s.label)).join(', ') || NA, t.flows[0]]),
});
REFERENCE.push({
  id: 'glossary', title: 'Glossary',
  intro: 'Plain-language meanings for the terms used across the flows. In each briefing, the first use of a term is underlined. Click it for the meaning.',
  cols: ['Term', 'What it means'],
  rows: GLOSSARY.map((g) => [`<b>${esc(g.term)}</b>`, esc(g.def)]),
});

/* ---------- suggested learning order ---------- */
const LEARN_PATH = ['auth-code-pkce', 'client-credentials', 'obo', 'agent-autonomous', 'agent-obo', 'mcp-auth', 'workiq-mcp'];
const DONE_KEY = 'authflow-done';
function doneFlows() { try { return new Set(JSON.parse(localStorage.getItem(DONE_KEY)) || []); } catch { return new Set(); } }
function markFlowDone(id) {
  const s = doneFlows(); if (s.has(id)) return;
  s.add(id); try { localStorage.setItem(DONE_KEY, JSON.stringify([...s])); } catch { /* storage blocked */ }
}
function learnPathHtml() {
  const done = doneFlows();
  const items = LEARN_PATH.map((id) => FLOWS.find((f) => f.id === id)).filter(Boolean);
  return `<div class="learn-path"><span class="soft" id="lpLabel">New here? Try them in this order:</span><ol aria-labelledby="lpLabel">${items.map((f, i) => {
    const d = done.has(f.id);
    return `<li><a href="#flow/${f.id}" class="${d ? 'done' : ''}"><span class="lp-n" aria-hidden="true">${d ? '✓' : i + 1}</span>${esc(f.title)}${d ? '<span class="sr-only">, finished</span>' : ''}</a></li>`;
  }).join('')}</ol></div>`;
}

/* ---------- copy as command, export ---------- */
const SECRET_KEYS = /^(client_secret|refresh_token|access_token|id_token|code_verifier|client_assertion|assertion|password|subject_token|actor_token|device_code)$/i;
// Placeholders, never values: what gets copied or exported can't carry a usable credential.
function scrubVal(k, v) {
  if (v == null || typeof v !== 'string') return v;
  if (/^authorization$/i.test(k) && /^bearer /i.test(v)) return 'Bearer <ACCESS_TOKEN>';
  if (SECRET_KEYS.test(k)) return `<${k.toUpperCase()}>`;
  // Authorization codes are long. Short "code" values are error names, such as Graph's InvalidAuthenticationToken.
  if (/^code$/i.test(k) && v.length > 40) return '<CODE>';
  if (isJwt(v)) return '<JWT>';
  // Codes and tokens can also ride inside a URL, such as a 302 Location to the redirect URI.
  return v.replace(/([?&#])(code|access_token|id_token|refresh_token|client_secret|code_verifier|client_assertion|password)=([^&#\s]+)/gi, (m, sep, name) => `${sep}${name}=<${name.toUpperCase()}>`)
    .replace(/eyJ[\w-]*\.[\w-]+\.[\w-]*/g, '<JWT>');
}
function scrubDeep(o, k = '') {
  if (typeof o === 'string') return scrubVal(k, o);
  if (Array.isArray(o)) return o.map((x) => scrubDeep(x, k));
  if (o && typeof o === 'object') return Object.fromEntries(Object.entries(o).map(([kk, v]) => [kk, scrubDeep(v, kk)]));
  return o;
}
function reqParts(req) {
  let base = req.url, query = req.query ? { ...req.query } : null;
  try {
    const u = new URL(req.url);
    if (u.search) { query = { ...Object.fromEntries(u.searchParams), ...(query || {}) }; base = `${u.origin}${u.pathname}`; }
  } catch { /* relative URL */ }
  const headers = Object.fromEntries(Object.entries(req.headers || {}).filter(([k]) => !/^(host|content-length)$/i.test(k)).map(([k, v]) => [k, scrubVal(k, String(v))]));
  return { method: (req.method || 'GET').toUpperCase(), base, query: query && scrubDeep(query), headers, form: req.form && scrubDeep(req.form), json: req.json !== undefined ? scrubDeep(req.json) : undefined, text: req.text };
}
const shq = (s) => `'${String(s).replace(/'/g, "'\\''")}'`;
const psq = (s) => `'${String(s).replace(/'/g, "''")}'`;
function curlCommand(req) {
  const p = reqParts(req), lines = [];
  const hasBody = p.form || p.json !== undefined || p.text;
  let url = p.base;
  if (p.query && hasBody) url += `?${new URLSearchParams(p.query)}`;
  if (p.query && !hasBody) {
    // -G sends the --data-urlencode pairs as the query string.
    lines.push(`curl -G${p.method === 'GET' ? '' : ` -X ${p.method}`} ${shq(url)}`);
    Object.entries(p.query).forEach(([k, v]) => lines.push(`  --data-urlencode ${shq(`${k}=${v}`)}`));
  } else lines.push(`curl${p.method === 'GET' ? '' : ` -X ${p.method}`} ${shq(url)}`);
  Object.entries(p.headers).forEach(([k, v]) => lines.push(`  -H ${shq(`${k}: ${v}`)}`));
  if (p.form) {
    if (!Object.keys(p.headers).some((k) => /^content-type$/i.test(k))) lines.push(`  -H ${shq('Content-Type: application/x-www-form-urlencoded')}`);
    Object.entries(p.form).forEach(([k, v]) => lines.push(`  --data-urlencode ${shq(`${k}=${v}`)}`));
  } else if (p.json !== undefined) {
    if (!Object.keys(p.headers).some((k) => /^content-type$/i.test(k))) lines.push(`  -H ${shq('Content-Type: application/json')}`);
    lines.push(`  --data-raw ${shq(JSON.stringify(p.json))}`);
  } else if (p.text) lines.push(`  --data-raw ${shq(p.text)}`);
  return lines.join(' \\\n');
}
function psCommand(req) {
  const p = reqParts(req), out = ['$request = @{', `  Method      = ${psq(p.method)}`];
  const hasBody = p.form || p.json !== undefined || p.text;
  out.push(`  Uri         = ${psq(p.query && hasBody ? `${p.base}?${new URLSearchParams(p.query)}` : p.base)}`);
  const ct = Object.entries(p.headers).find(([k]) => /^content-type$/i.test(k));
  const hdrs = Object.entries(p.headers).filter(([k]) => !/^content-type$/i.test(k));
  if (hdrs.length) out.push(`  Headers     = @{ ${hdrs.map(([k, v]) => `${psq(k)} = ${psq(v)}`).join('; ')} }`);
  const table = (o) => `@{\n${Object.entries(o).map(([k, v]) => `    ${psq(k)} = ${psq(typeof v === 'string' ? v : JSON.stringify(v))}`).join('\n')}\n  }`;
  if (p.form) { out.push(`  ContentType = ${psq(ct ? ct[1] : 'application/x-www-form-urlencoded')}`, `  Body        = ${table(p.form)}`); }
  else if (p.json !== undefined) { out.push(`  ContentType = ${psq(ct ? ct[1] : 'application/json')}`, `  Body        = ${psq(JSON.stringify(p.json))}`); }
  else if (p.text) { if (ct) out.push(`  ContentType = ${psq(ct[1])}`); out.push(`  Body        = ${psq(p.text)}`); }
  else if (p.query) out.push(`  Body        = ${table(p.query)}`); // On GET, Invoke-RestMethod turns Body into the query string.
  out.push('}', 'Invoke-RestMethod @request');
  return out.join('\n');
}
async function copyText(text, what) {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch {
    const ta = document.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { ok = document.execCommand('copy'); } catch { ok = false; }
    ta.remove();
  }
  toast(ok ? `Copied ${what}.` : `Couldn't copy ${what}. Your browser blocked the clipboard.`, 3000);
  announce(ok ? `Copied ${what}.` : `Couldn't copy ${what}.`);
  return ok;
}
function runExport(player) {
  const f = player.flow;
  const data = {
    tool: 'AuthFlowMap', flow: f.id, title: f.title, variant: player.variant || null, mode: player.mode, exported: new Date().toISOString(),
    note: 'Secrets, codes and tokens are replaced with placeholders. Token claims are kept, signatures are not.',
    steps: player.steps.map((s, i) => ({
      n: i + 1, title: s.title, from: s.from, to: s.to, determinism: s.det, status: s.status, source: s.src,
      request: s.req ? scrubDeep(s.req) : null, response: s.res ? scrubDeep(s.res) : null,
      tokens: s.tokens.map((t) => ({ label: t.label || t.field || null, field: t.field || null, header: t.header || null, claims: t.payload || null })),
      checks: s.checks, values: s.kv ? scrubDeep(s.kv) : null,
    })),
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `authflow-${f.id}${player.variant ? `-${player.variant}` : ''}-${data.exported.slice(0, 19).replace(/[:T]/g, '-')}.json`;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast('Downloaded the run as JSON.', 3000);
}
function stepLink(player) {
  const p = new URLSearchParams();
  if (player.flow.variants && player.variant) p.set('variant', player.variant);
  if (player.idx >= 0) p.set('step', String(player.idx + 1));
  p.set('view', APP.view);
  return `${location.href.split('#')[0]}#flow/${player.flow.id}?${p}`;
}

/* ---------- AADSTS lookup ---------- */
function aadstsFlows(code) {
  return FLOWS.filter((f) => {
    const src = `${typeof f.steps === 'function' ? f.steps.toString() : ''} ${JSON.stringify(f.variants || [])} ${f.brief ? JSON.stringify(f.brief) : ''}`;
    return new RegExp(`AADSTS${code}\\b`).test(src);
  });
}
