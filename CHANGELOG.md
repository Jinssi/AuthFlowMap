# Changelog

### 2026-11-03

**Global Secure Access and Zero Trust.** A new section based on the Entra blog posts "Global Secure Access: Private Access and Internet Access in one offering" and "Secure AI, web, and private apps with Zero Trust", and the Learn pages they link.
- **Private Access instead of a VPN.** Per-app access to an on-premises RDP server through a private network connector, with variants for a personal laptop (BYOD) and for printing at home with home network support.
- **Internet Access: security profiles.** Profiles linked through Conditional Access, an exception profile with the Continue default action, the baseline profile, threat intelligence and the cloud firewall.
- **Browser access without the client.** The explicit forward proxy: PAC file, Entra sign-in, Conditional Access and the same security profiles.
- **Compliant network against token theft.** Source IP restoration, and a stolen token stopped on both the data plane (Graph) and the authentication plane (Entra).
- **Universal CAE.** An RDP session that ends when the laptop falls out of compliance, and one that survives when the user fixes their own risk.
- **AI apps and data in motion.** Network DLP with Purview, prompt injection protection and custom headers, with TLS inspection.
- **Network controls for AI agents.** Agentic Acquire with Shadow MCP logging, Windows 365 for Agents and Copilot Studio agents.

**Architecture and decisions**
- A Global Secure Access zone with the client, the edge, private network connectors and Purview, in all three layouts. The bow-tie gives it its own "Enforce on traffic" column.
- Steps at the Global Secure Access edge carry the Entra policy badge and the Authorize stage. The edge enforces Entra configuration but never issues tokens.

**Reference and learning aids**
- Reference tables for Global Secure Access and for Zero Trust across the tabs.
- Ten new glossary terms, six new threats and three documentation link groups.

**Project**
- The README is now a short introduction, getting started and license. This changelog moved here.
- MIT license.
- A new README screenshot of the Agent ID on-behalf-of flow.

### 2026-10-29

**Who decides, made explicit.** This answers a reader's question: does the tool separate token issuance and validation from the resource's own authorization decision?
- The old Policy badge is now two badges. **Entra policy** covers decisions Entra makes before it issues a token. **Resource policy** covers decisions the API, MCP server or data service makes with its own rules.
- **Issue**, **Validate** and **Authorize** stage chips on every step that decides something.
- On a receiver step the Checks tab splits into **Token valid?** and **Allowed to do this?**.
- The recap names **who said no**, at which stage and in which step.
- The Step-up tab has a new **Agent acting for the user** variant. The API accepts the agent's valid token and still refuses a 12 400 EUR approval until the user steps up with a passkey through Conditional Access.

**Architecture page**
- Two new layouts next to the columns: **Bow-tie** (ask for tokens, issue tokens, accept tokens) and **Hub and spoke** with Entra ID in the centre.
- All three layouts share one zoom level.
- The "All connections" toggle is gone. Click a component to light up its connections.

**Zoom, layout and presenting**
- Fit never shrinks diagram text below 12 px. Pan by dragging or with the arrow keys, and zoom with +, − and 0 or Ctrl and the mouse wheel.
- The side menu slides in from ☰ on narrow windows and at high browser zoom. Each tab name stays on one line.
- Presenter mode (P) enlarges the text and hides the menu and briefing.
- Overflow fixes, including long claim names in the decoded token table.

**Accessibility**
- Landmarks, labels and live announcements for screen readers.
- Visible focus and full keyboard control.
- The page passes WCAG 2.2 AA checks with axe-core in both themes.

**Learning aids**
- A suggested learning order that ticks off finished flows.
- Glossary definitions on dotted terms.
- A recap at the end of each run.
- Deep links to any tab, variant, view and step.
- Copy a request as curl or PowerShell, and export a run as JSON. Secrets, codes and tokens always become placeholders.
- A folded list of threats in each briefing, with the RFC 9700 section and MITRE technique.
- An AADSTS error lookup in the Reference filter.

**Live mode hardening**
- The server picks every run ID and protects each trace with a key.
- Rate limits and caps on traces.
- Masking on values as well as field names.
- MCP sessions are bound to the token that opened them.
- Client secrets now last 30 days by default (`-SecretLifetimeDays`).
- `Remove-AuthFlowTenant.ps1` also deletes `.env`.

**Tests and CI**
- A Playwright and axe-core UI suite: layout, accessibility, interaction and learning aids for every tab.
- A build check that `index.html` matches the sources.
- GitHub Actions runs everything on each push and checks the documentation links weekly.

`index.html` is still one file with no dependencies. Everything above lives inside it, except the server and the tests.

### 2026-10-02

- IQ and grounded agents section: Work IQ over MCP, Foundry IQ knowledge base, Foundry IQ + Work IQ, and oversharing.
- A stricter documentation link check.

### 2026-09-30

- First release.
- Confidential web app flow and the Documentation links page.
