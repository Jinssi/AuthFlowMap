// Phase 4 features: deep links, copy and export, glossary toggletips, learning order, threats and the AADSTS lookup.
import AxeBuilder from '@axe-core/playwright';
import { readFileSync } from 'node:fs';
import { test, expect, open, FLOWS } from './helpers.mjs';

const JWT = /eyJ[\w-]*\.[\w-]+\.[\w-]+/;
const SIM_CODE = /1\.AR8A[\w-]{20,}/; // The simulated authorization code and refresh token prefix.

test.use({ viewport: { width: 1920, height: 1000 } });

test.describe('deep links', () => {
  test('open the variant, step and view from the URL', async ({ page }) => {
    await open(page, '#flow/auth-code-pkce?variant=stolen-code&step=3&view=sequence');
    await expect(page.locator('input[name=variant][value="stolen-code"]')).toBeChecked();
    await expect(page.locator('.step-item[aria-current="step"]')).toHaveAttribute('data-i', '2');
    await expect(page.locator('[data-view="sequence"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('details.briefing')).not.toHaveAttribute('open', '');
    await expect(page.locator('.nav-item[href="#flow/auth-code-pkce"]')).toHaveAttribute('aria-current', 'page');
  });

  test('an out-of-range step or unknown variant falls back to the start', async ({ page }) => {
    await open(page, '#flow/obo?variant=nope&step=999');
    await expect(page.locator('input[name=variant]').first()).toBeChecked();
    await expect(page.locator('.step-item[aria-current="step"]')).toHaveCount(0);
  });

  test('Copy link round-trips to the same step', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await open(page, '#flow/obo');
    await page.locator('input[name=variant][value="wrong-aud"]').check();
    await page.evaluate(() => APP.player.goTo(1));
    await page.locator('[data-act=link]').click();
    const link = await page.evaluate(() => stepLink(APP.player));
    expect(link).toMatch(/#flow\/obo\?variant=wrong-aud&step=2&view=diagram$/);
    await open(page, link.slice(link.indexOf('#')));
    await expect(page.locator('input[name=variant][value="wrong-aud"]')).toBeChecked();
    await expect(page.locator('.step-item[aria-current="step"]')).toHaveAttribute('data-i', '1');
  });
});

test.describe('copy and export never carry credentials', () => {
  for (const f of FLOWS.filter((x) => x.kind === 'flow')) {
    test(`${f.id}: curl, PowerShell and export use placeholders`, async ({ page }) => {
      await open(page, `#flow/${f.id}`);
      const leaks = await page.evaluate(async ({ jwt, code }) => {
        const bad = [];
        const reJwt = new RegExp(jwt), reCode = new RegExp(code);
        for (const v of FLOWS.find((x) => x.id === APP.player.flow.id).variants?.map((x) => x.id) || [null]) {
          if (v) { APP.player.variant = v; await APP.player.prepareSim(); }
          APP.player.steps.forEach((s, i) => {
            const texts = s.req ? [curlCommand(s.req), psCommand(s.req)] : [];
            texts.push(JSON.stringify({ req: scrubDeep(s.req), res: scrubDeep(s.res), kv: scrubDeep(s.kv) }));
            texts.forEach((t) => { if (reJwt.test(t) || reCode.test(t) || /client_secret=(?!<)/.test(t)) bad.push(`${v || 'default'} step ${i + 1}: ${t.slice(0, 120)}`); });
          });
        }
        return bad;
      }, { jwt: JWT.source, code: SIM_CODE.source });
      expect(leaks).toEqual([]);
    });
  }

  test('Export run downloads masked JSON', async ({ page }) => {
    await open(page, '#flow/auth-code-pkce');
    await page.evaluate(() => APP.player.goTo(APP.player.steps.length - 1));
    const [dl] = await Promise.all([page.waitForEvent('download'), page.locator('[data-act=export]').click()]);
    expect(dl.suggestedFilename()).toMatch(/^authflow-auth-code-pkce-.+\.json$/);
    const { readFile } = await import('node:fs/promises');
    const text = await readFile(await dl.path(), 'utf8');
    const data = JSON.parse(text);
    expect(data.flow).toBe('auth-code-pkce');
    expect(data.steps.length).toBeGreaterThan(5);
    expect(text).not.toMatch(JWT);
    expect(text).not.toMatch(SIM_CODE);
  });

  test('the Request tab offers curl and PowerShell copies', async ({ page, context }) => {
    await context.grantPermissions(['clipboard-read', 'clipboard-write']);
    await open(page, '#flow/client-credentials');
    await page.evaluate(() => { const i = APP.player.steps.findIndex((s) => s.req?.form); APP.player.goTo(i); });
    await page.locator('[data-tab="request"]').click();
    await page.locator('[data-copy="curl"]').click();
    const clip = await page.evaluate(() => navigator.clipboard.readText());
    expect(clip).toMatch(/^curl -X POST '/);
    expect(clip).toContain('--data-urlencode');
    expect(clip).not.toMatch(JWT);
    await page.locator('[data-copy="pwsh"]').click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toContain('Invoke-RestMethod @request');
  });
});

test.describe('learning aids', () => {
  test('glossary toggletip opens with the keyboard and closes with Escape', async ({ page }) => {
    await open(page, '#flow/obo');
    const term = page.locator('.brief-grid .gloss').first();
    await expect(term).toBeVisible();
    await term.focus();
    await page.keyboard.press('Enter');
    await expect(term).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('#glossTip')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('#glossTip')).toBeHidden();
    await expect(term).toHaveAttribute('aria-expanded', 'false');
    await expect(term).toBeFocused();
  });

  test('each glossary term is marked once per briefing', async ({ page }) => {
    await open(page, '#flow/agent-obo');
    const terms = await page.locator('.brief-grid .gloss').evaluateAll((els) => els.map((e) => e.dataset.term));
    expect(terms.length).toBeGreaterThan(0);
    expect(new Set(terms).size).toBe(terms.length);
  });

  test('finishing a flow ticks it in the learning order and shows a recap', async ({ page }) => {
    await open(page, '#architecture');
    await expect(page.locator('.learn-path a[href="#flow/client-credentials"]')).not.toHaveClass(/done/);
    await open(page, '#flow/client-credentials');
    await page.evaluate(() => APP.player.goTo(APP.player.steps.length - 1));
    await expect(page.locator('#inspector .recap')).toBeVisible();
    await open(page, '#architecture');
    await expect(page.locator('.learn-path a[href="#flow/client-credentials"]')).toHaveClass(/done/);
  });

  test('briefings list the threats a flow stops, with MITRE and RFC links', async ({ page }) => {
    await open(page, '#flow/auth-code-pkce');
    const t = page.locator('details.threats');
    await t.locator('summary').click();
    await expect(t.locator('a[href*="attack.mitre.org/techniques/T1528"]').first()).toBeVisible();
    await expect(t.locator('a[href*="rfc9700#section-4.5"]')).toBeVisible();
  });

  test('a pasted AADSTS error filters the reference and names the flows', async ({ page }) => {
    await open(page, '#reference');
    await page.locator('#refFilter').fill('AADSTS50013: The assertion audience claim does not match');
    await expect(page.locator('#refCount')).toContainText('AADSTS50013');
    await expect(page.locator('#refLookup a[href="#flow/obo"]')).toBeVisible();
    await expect(page.locator('#ref-errors')).toBeVisible();
    await page.locator('#refFilter').fill('');
    await expect(page.locator('#refLookup')).toBeHidden();
  });
});

test.describe('issue, validate and authorize', () => {
  test('the agent step-up keeps a valid token apart from the API\'s own decision', async ({ page }) => {
    await open(page, '#flow/step-up?variant=agent');
    const i = await page.evaluate(() => APP.player.steps.findIndex((s) => s.id === 'sa-validate'));
    expect(i).toBeGreaterThan(0);
    await page.evaluate((n) => APP.player.goTo(n), i);
    const row = page.locator(`.step-item[data-i="${i}"]`);
    await expect(row.locator('.det-resource')).toHaveText('Resource policy');
    await expect(row.locator('.stage-validate')).toContainText('Validate');
    await expect(row.locator('.stage-authorize')).toContainText('Authorize');
    await page.locator('#inspector [data-tab="checks"]').click();
    const heads = page.locator('#inspector .checks-h');
    await expect(heads).toHaveCount(2);
    await expect(heads.nth(0)).toContainText('Token valid?');
    await expect(heads.nth(0).locator('.checks-verdict')).toHaveText('Yes');
    await expect(heads.nth(1)).toContainText('Allowed to do this?');
    await expect(heads.nth(1).locator('.checks-verdict')).toHaveText('No');
  });

  test('Entra decisions and resource decisions get different badges', async ({ page }) => {
    await open(page, '#flow/step-up?variant=agent');
    const dets = await page.evaluate(() => Object.fromEntries(APP.player.steps.map((s) => [s.id, s.det])));
    expect(dets['sa2-policy']).toBe('policy');
    expect(dets['sa-challenge']).toBe('resource');
    await open(page, '#flow/workiq-mcp');
    expect(await page.evaluate(() => APP.player.steps.find((s) => s.id === 'wq-deny').det)).toBe('resource');
  });

  test('the recap names who said no, and says so when nobody did', async ({ page }) => {
    await open(page, '#flow/step-up?variant=agent');
    await page.evaluate(() => APP.player.goTo(APP.player.steps.length - 1));
    await expect(page.locator('#inspector .recap')).toContainText(/Who said no: Orders API, at the Authorize stage/);
    await open(page, '#flow/aitm?variant=push');
    await page.evaluate(() => APP.player.goTo(APP.player.steps.length - 1));
    await expect(page.locator('#inspector .recap')).toContainText('Who said no: nobody');
  });

  for (const theme of ['dark', 'light']) {
    test(`axe on the split checks and stage chips (${theme})`, async ({ page }) => {
      await page.addInitScript((t) => localStorage.setItem('authflow-theme', t), theme);
      await open(page, '#flow/step-up?variant=agent');
      await page.evaluate(() => APP.player.goTo(APP.player.steps.findIndex((s) => s.id === 'sa-validate')));
      await page.locator('#inspector [data-tab="checks"]').click();
      const { violations } = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
      expect(violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(', ')}`)).toEqual([]);
    });
  }
});

test('axe on the opened learning aids', async ({ page }) => {
  await open(page, '#flow/auth-code-pkce');
  await page.locator('details.threats summary').click();
  await page.locator('.brief-grid .gloss').first().click();
  await page.evaluate(() => APP.player.goTo(APP.player.steps.length - 1));
  const { violations } = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
  expect(violations.filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).slice(0, 3).join(', ')}`)).toEqual([]);
});

// Live mode needs the local server and a tenant, so this serves the built page over http and answers /api/health as a
// fully configured server. Break-it variants must still run as simulations: no sign-in popup and no server calls.
test.describe('break-it variants in Live mode', () => {
  const HTML = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  const BREAK_IT = [['auth-code-pkce', 'stolen-code', 'unknown'], ['obo', 'wrong-aud', 'valid'], ['mcp-obo', 'passthrough', 'bound']];
  for (const [flow, broken, good] of BREAK_IT) {
    test(`${flow} ${broken} stays simulated`, async ({ page }) => {
      const calls = [];
      await page.route('http://localhost:5100/**', (r) => {
        const { pathname } = new URL(r.request().url());
        if (pathname === '/') return r.fulfill({ contentType: 'text/html', body: HTML });
        if (pathname === '/api/health') return r.fulfill({ json: { live: true, tenantId: '00000000-0000-0000-0000-000000000000', flows: { [flow]: true } } });
        calls.push(pathname); return r.fulfill({ status: 500, json: {} });
      });
      page.on('popup', (p) => calls.push(`popup ${p.url()}`));
      await page.goto(`http://localhost:5100/#flow/${flow}?variant=${good}`);
      await page.waitForFunction(() => document.querySelectorAll('.step-item').length > 0 && document.querySelector('#liveStatus.ok'));
      await page.click('.mode-switch button[data-mode="live"]');
      await expect(page.locator('#modePill')).toHaveText(/LIVE against a real Entra tenant/);
      await page.check(`input[name=variant][value="${broken}"]`);
      await expect(page.locator('#modePill')).toHaveText('Simulation only for this variant');
      await page.click('#btnPlay');
      await expect(page.locator('#toast')).toContainText('only exists as a simulation');
      await expect(page.locator('.step-item[aria-current="step"]')).toBeVisible();
      expect(calls).toEqual([]);
    });
  }
});
