# AuthFlowMap

An interactive map of how modern authentication actually works, one HTTP request at a time. It covers standard OAuth 2.0 and OIDC, Conditional Access, MFA, devices and risk, Microsoft Entra Agent ID, MCP authorization under the 2025-11-25 spec, chains of agents calling each other, and how Work IQ and Foundry IQ keep an agent's answers limited to what the asking user may see.

I built it to explain these flows to a room without hand-waving. Every step shows who sends what to whom, what the token contains, what gets checked and who made the decision.

![A flow tab mid-run: the Agent ID on-behalf-of exchange, with the diagram, step list and decoded token](docs/screenshot-flow.png)

## Quick start

Open `demonstrator/index.html` in Edge or Chrome. It's a single file with no dependencies and no network calls, so it also works offline.

## How to read the screen

**The side menu** groups the tabs. Start with Architecture, then pick a flow. On narrower windows or high browser zoom it slides in from the ☰ button instead of taking up space. Each tab is one row; hover a shortened name to see it in full. The top of each flow tab says whether it can also run against a real tenant (Runs live) and whether it relies on features Microsoft still lists as preview.

**The architecture page** has three layouts. Columns groups the components by zone. Bow-tie reads left to right: everything that asks for tokens, Entra ID in the knot, everything that accepts them. Hub and spoke puts Entra ID in the centre with each zone in its own slice around it. In the last two, solid lines are token requests to Entra ID, dotted lines are trust between identity services and faint dashed lines are calls between components. Click a component to light up only its connections. The page remembers the layout you picked, and all three share one zoom level.

**The briefing** at the top of each flow tab says what the flow is for, what has to be set up and the anti-pattern it prevents, and links to the documentation behind it. Read it before pressing Start. It folds away once the flow runs.

**The controls** play, pause and step through the flow. Components shows the hops on an architecture diagram. Sequence shows the same messages as a sequence diagram. Some tabs have variants, such as a managed versus an unknown device, that change the steps.

**The diagram** highlights one hop at a time. Fit sizes it to the space but never shrinks the text below a readable size. When it is larger than the space, drag it or use the arrow keys to pan. The −, + and 100% buttons, the + and − keys, or Ctrl with the mouse wheel zoom it, and 0 goes back to Fit. Each diagram type remembers its zoom.

- The component glowing mint and marked SENDING is the sender.
- The component glowing rose and marked RECEIVING is the receiver.
- A component with a dashed, moving border and PROCESSING is working on its own, for example validating a token.
- The small pill travelling along the arrow is the message. Its label names the token or HTTP method it carries.
- Violet arrows are hops that already happened. Dashed grey arrows are hops still to come.

**The badge on every step** says who decided it.

| Badge | Meaning |
|---|---|
| Protocol | Fixed protocol logic. The same input always gives the same output |
| AI decision | The language model chose this, so another run might differ. Access never depends on it |
| Human | A person signed in, approved something or typed a code |
| Entra policy | Entra applied configuration before issuing anything, such as Conditional Access, consent, app roles or cross-tenant access |
| Resource policy | The API, MCP server or data service decided with its own rules after the token was valid, such as scopes, authentication context, data permissions or business limits |

**Stage chips** next to the badge separate three decisions that are easy to blur. **Issue**: Entra, or another identity provider, decides whether to issue a token. **Validate**: the receiver checks the token is genuine, current and meant for it. **Authorize**: the receiver decides whether this caller may do this action now. A valid token is not permission. The agent variant of the Step-up tab shows an API that accepts the agent's token and still refuses a 12 400 EUR approval until the user steps up. On a receiver step the Checks tab splits into **Token valid?** and **Allowed to do this?**, and the recap at the end names **who said no**, at which stage and in which step.

**Present** (key P) enlarges the text and hides the side menu and briefing for screen sharing. Esc leaves it.

**The inspector** on the right, or under the diagram in a narrow window, has five tabs. Keys 1 to 5 switch between them.

- **Overview** explains the step in plain words, and why it matters.
- **Request** and **Response** show the raw HTTP, with secrets and token signatures masked.
- **Tokens** decodes every JWT in the step. Highlighted rows are the claims worth pointing at, and each claim has a one-line explanation.
- **Checks** lists what the receiver verified, with a tick or a cross.

**The step list** under the diagram shows every step. Click any step to jump to it.

**The Conditional Access simulator** works differently. Pick a scenario or flip the switches on the left, and the right side shows the decision, what the user experiences, which sample policies applied and what ends up in the token.

![The Conditional Access simulator with an unknown home PC scenario](docs/screenshot-ca-simulator.png)

**The Reference tab** has tables for grant types, delegation models, consent, authentication methods, device states, Conditional Access, hybrid identity, external identities, governance, agent identities, MCP, the IQ products, oversharing controls, token claims, anti-patterns and common errors. The filter box searches all of them. The first table, also in the side menu as Documentation links, collects every public document the tabs are based on: Microsoft Learn, the MCP specification and the IETF RFCs.

**The IQ and grounded agents tabs** follow one question: whose identity reaches the data? Work IQ over MCP shows the four layers that decide each tool call: Entra sign-in, the delegated `WorkIQAgent.Ask` permission, the user's Microsoft 365 permissions and the tenant policy that blocks writes by default. Foundry IQ knowledge base shows a retrieve call that carries two identities, the agent's managed identity and the user's token, and Azure AI Search trimming results to the user's ACLs. Foundry IQ + Work IQ shows Azure AI Search running OBO through a federated credential so Microsoft 365 is still read as the user. Oversharing runs the same salary question three ways, and only one of them keeps the file away from a contractor. These four tabs are simulated only.

**Learning aids** are there for whoever is in the room.

- **New to identity.** The architecture page suggests a learning order and ticks each flow you finish. Dotted terms in a briefing, such as PKCE or audience, open a one-line definition; Esc closes it. Finishing a flow shows a recap at the top of Overview: the tokens issued, the checks that ran and the anti-pattern to avoid. The Reference tab ends with the full glossary.
- **Engineers.** The address bar keeps the tab, variant, view and step, for example `#obo?variant=wrong-aud&step=6&view=sequence`. Copy link to this step, under the step list, gives you that link. The Request tab copies the request as curl or PowerShell, and Export run saves the whole run as JSON. Secrets, codes and tokens always become placeholders such as `<ACCESS_TOKEN>`. Paste an `AADSTS` error into the Reference filter to see its meaning and the tabs that show it.
- **Security reviewers.** Each briefing has a folded list of the threats the flow stops, with the RFC 9700 section, the MITRE ATT&CK or ATLAS technique and the control that blocks it. Three tabs have a variant that breaks on purpose: a stolen authorization code without its PKCE verifier (auth code + PKCE), an API token passed on to a second API (OBO) and an MCP server forwarding the client's token (MCP OBO). They run as simulations only, in Live mode too.

Keyboard: Space starts and pauses, the arrow keys step, R resets, V switches the view, + − 0 zoom the diagram, P toggles presenter mode, N shows or hides the side menu and ? shows help.

![The architecture overview with Microsoft Entra ID selected](docs/screenshot-architecture.png)

## Two modes

**Simulated** is the default and needs nothing. The requests look real and the tokens decode like real JWTs, but they're fake and unsigned, built from a fictitious Contoso tenant. The PKCE challenge is a real SHA-256 of the verifier.

**Live** runs the same tabs against an Entra test tenant you own. A local Node server does the confidential-client work: OBO, client credentials, device code, the Agent ID exchanges and a small MCP server. The browser does the auth code + PKCE sign-in in a popup and plays the MCP client. Every request is recorded as it happens and replayed at a speed you can talk over. Steps tagged REAL are real traffic. Steps tagged SIM are the language model steps, since the demo server has no model.

Fourteen tabs run live, including the confidential web app, where the local server plays the web app back end and redeems the code with its own secret or certificate. Refresh and CAE, managed identity, workload identity federation, the agent's user account, the multi-agent chain and the IQ tabs stay simulated. The IQ tabs would need Microsoft 365 Copilot licenses, Work IQ billing and an Azure AI Search service, which is more than a demo tenant should carry. The access, MFA and devices tabs go live in their own way, because nobody wants a real phishing attack in a meeting.

- **Conditional Access simulator.** The same switches go to Graph's What If API, and your tenant's real policies answer.
- **Step-up MFA.** The API really returns a claims challenge, you really step up, and the retry succeeds with `acrs` in the token. Needs `-EnableStepUpPolicy` at provisioning.
- **Session theft.** Signs you in, shows the `amr` in your real token, lists your registered methods and marks which ones resist phishing.
- **Device identity.** Signs you in from this browser and shows whether the token carries a `deviceid`. Try it from a managed Windows laptop in Edge, then from a personal browser.
- **Identity Protection.** Reads your tenant's latest risk detections and risky users.

Conditional Access, What If and step-up need Entra ID P1. Risk data needs P2.

## Setting up Live mode

You need PowerShell 7, Node 20 or later and a test tenant where you're allowed to create app registrations and grant admin consent.

```powershell
# 1. Provision the test tenant. Creates the apps, the Agent ID blueprint, one agent identity and all grants, then writes .env
pwsh ./provisioning/New-AuthFlowTenant.ps1 -TenantId <tenant-guid>
#    add -SkipAgentId if Agent ID isn't enabled in the tenant, or -SkipCertificate to skip the daemon cert
#    add -EnableStepUpPolicy for the live step-up tab. It creates authentication context c1 and a policy
#    scoped to the demo user only. -DemoUserUpn picks the demo user, otherwise it's you
#    client secrets last 30 days. Change it with -SecretLifetimeDays (1 to 180)

# 2. Start the local server. It binds to 127.0.0.1 only
cd server
npm install
npm start

# 3. Open http://localhost:5100 and flip the switch in the top right to Live
```

New permissions take 30 to 120 seconds to reach the token service. If the first live run fails with a consent error, wait a minute and try again. To remove everything, run `pwsh ./provisioning/Remove-AuthFlowTenant.ps1 -TenantId <tenant-guid>`. It also deletes `.env`, because the secrets in it belong to the deleted apps. Add `-KeepEnv` to keep it.

To skip the script, copy `.env.example` to `.env` at the repo root and fill it in yourself. Register the SPA redirect URI `http://localhost:5100/auth-callback` under the SPA platform and turn on public client flows.

### Safety

Use a test tenant. The API, MCP server and blueprint authenticate with client secrets here because a laptop has no managed identity. Each tab says what production should use instead.

Secrets live in `.env` and the server process, and `.env` is gitignored. The browser never gets them. On screen, tokens show a short prefix of the header and payload and the signature is always cut. The decoded claims show in full, because that's the part worth explaining.

The server rejects any Host header that isn't loopback, rejects cross-origin POSTs and sends no CORS headers.

The server picks every run ID. Starting a run returns the ID and a random trace key, and the page sends the key in an `X-Trace-Key` header to read the trace. A wrong key and an unknown run get the same 404, so another process on the laptop can't read or guess a trace.

The server allows 4 server-side runs at a time and 30 run starts a minute. Past that it answers 429 with `Retry-After`. It keeps at most 100 traces, each for 30 minutes, with a cap on events and size.

Masking works on field names and on values. Anything that looks like a JWT, a refresh token, an authorization code, a client secret or a Bearer value is masked wherever it appears in a trace, including error text and query strings. Error text the web app shows back is escaped and cut to 300 characters.

The MCP server binds each `Mcp-Session-Id` to the tenant, user and client in the token that opened it. An unknown session gets 404. A token from someone else gets 403.

## Making it your own

To rebrand the simulated tenant, change the names and IDs in the `ID` block of `demonstrator/src/config.js`. The colours sit at the top of `demonstrator/src/styles.css`. The page defaults to dark. Add `?theme=light` to the URL, or use the ◐ button, for the light version.

After changing anything in `demonstrator/src`, rebuild the single file with `npm run build`. `npm test` runs the server tests, and `npm run check:links` checks every documentation link. A link fails if it returns an error, redirects anywhere, or serves a "page not found" page, so a moved page shows up before a customer clicks it.

### Tests

The UI tests use Playwright and axe-core. Both are dev-only dependencies at the repository root; `index.html` itself stays dependency-free. Install once with `npm install` and `npx playwright install chromium`.

| Command | What it checks |
|---|---|
| `npm test` | The server: token calls, trace store, MCP server |
| `npm run check:build` | `index.html` matches what `npm run build` would produce from `src` |
| `npm run test:ui` | Every tab at 1920 px 100%, a laptop at 150% and 1920 px at 200%, in both themes: no sideways overflow, diagram text at least 12 px, every step label inside its pill. WCAG 2.2 AA with axe-core, where serious or critical findings fail. Keyboard, focus, zoom, drawer and presenter behaviour. Deep links, the glossary, learning order, recap, threats and AADSTS lookup, and that copy as curl/PowerShell and Export run never carry a secret or token for any variant |
| `npm run test:all` | All three in a row |

`npx playwright test --ui` opens the interactive runner, and `npx playwright test -g "axe light"` runs a subset. A new flow is picked up automatically because the suite reads the flow list from `src`. GitHub Actions runs `test:all` on every push and pull request, and checks the documentation links every Monday.

```
demonstrator/
  src/                 # styles, flow definitions, reference tables, engine, live client
  test/                # Playwright UI suite: layout, accessibility, interaction, learning aids
  build.mjs            # inlines src/* into a single index.html, --check verifies it is current
  index.html           # the built file you open
server/                # Express + jose backend: raw /token calls, trace store, MCP server
provisioning/          # New-AuthFlowTenant.ps1 and Remove-AuthFlowTenant.ps1, both via Microsoft Graph
docs/                  # screenshots
```

## Accuracy

The Agent ID steps (`fmi_path`, agent OBO, `user_fic`) and the `xms_*` claims follow three public Microsoft Learn pages: "Agent OAuth flows: On-behalf-of flow", "Agent's user account impersonation protocol" and "Token claims reference for agent IDs". Agent ID still changes often, so reread them before you rely on a detail.

Entra doesn't support Client ID Metadata Documents or Dynamic Client Registration, so the MCP flows use a pre-registered client. In Live mode the MCP authorization tab also checks whether your tenant's discovery document lists `code_challenge_methods_supported`. The spec tells clients to refuse to continue when that field is missing.

The Conditional Access simulator's offline engine is a teaching model of a sample policy set. It isn't Entra's evaluation logic. For real answers, use Live mode, which asks Graph's What If API.

The IQ tabs follow the Work IQ MCP, Work IQ permissions and policy governance pages, "Connect agents to Foundry IQ knowledge bases", "Query-time ACL and RBAC enforcement", "Query a knowledge base" and "Create a Work IQ knowledge source". Most of what they show is preview, API version `2026-08-01-preview` at the time of writing. Two Learn pages disagree on what a permission-enabled index returns when the user token is missing, so the tab tells you to always send it rather than picking a side. The Work IQ policy-denied error body is illustrative.

## Changelog

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

## Disclaimer

This is an independent educational project. It isn't affiliated with or endorsed by Microsoft. Contoso and every user, app and ID in Simulated mode are fictitious. Microsoft, Entra and related names are trademarks of their owners.
