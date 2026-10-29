// Accessibility: axe-core with the WCAG 2.2 AA rule set. Serious and critical findings fail the build.
import AxeBuilder from '@axe-core/playwright';
import { test, expect, open, ROUTES, THEMES } from './helpers.mjs';

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'];
// The inspector tabs and the sequence view come from the same renderer for every flow, so a spread of flow kinds covers them.
const DEEP = ['#flow/auth-code-pkce', '#flow/obo', '#flow/device-code', '#flow/agent-obo', '#flow/mcp-auth', '#flow/iq-oversharing'];

async function axe(page, include) {
  let b = new AxeBuilder({ page }).withTags(TAGS);
  if (include) b = b.include(include);
  const { violations } = await b.analyze();
  return violations
    .filter((v) => v.impact === 'serious' || v.impact === 'critical')
    .map((v) => `${v.id} (${v.impact}): ${v.help}\n    ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join('\n    ')}${v.nodes.length > 3 ? `\n    …and ${v.nodes.length - 3} more` : ''}`);
}

for (const theme of THEMES) {
  test.describe(`axe ${theme}`, () => {
    test.use({ viewport: { width: 1920, height: 1000 } });
    for (const r of ROUTES) {
      test(r.hash, async ({ page }) => {
        await open(page, r.hash, { theme });
        // Step into a flow first so the inspector and the active edge label are part of the full-page pass.
        if (r.kind === 'flow') await page.evaluate(() => APP.player.goTo(Math.min(APP.player.steps.length - 1, 5)));
        expect(await axe(page)).toEqual([]);
      });
    }
  });
}

test.describe('axe inspector tabs and sequence view', () => {
  test.use({ viewport: { width: 1920, height: 1000 } });
  for (const hash of DEEP) {
    test(hash, async ({ page }) => {
      await open(page, hash);
      await page.evaluate(() => APP.player.goTo(Math.min(APP.player.steps.length - 1, 5)));
      const found = [];
      for (const tab of ['request', 'response', 'tokens', 'checks']) {
        const ok = await page.evaluate((t) => { const b = document.querySelector(`[data-tab="${t}"]`); if (!b || b.disabled) return false; b.click(); return true; }, tab);
        if (ok) found.push(...(await axe(page, '#inspector')).map((v) => `[${tab} tab] ${v}`));
      }
      await page.evaluate(() => APP.player.setView('sequence'));
      found.push(...(await axe(page, '#stageView')).map((v) => `[sequence] ${v}`));
      expect(found).toEqual([]);
    });
  }
});

test.describe('axe architecture layouts', () => {
  test.use({ viewport: { width: 1920, height: 1000 } });
  for (const theme of THEMES) {
    test(`bow-tie and hub with a selection, ${theme}`, async ({ page }) => {
      await open(page, '#architecture', { theme });
      const found = [];
      for (const view of ['bowtie', 'hub']) {
        await page.locator(`#archTab-${view}`).click();
        await page.locator('#archSvg .node[data-actor="entra"]').click();
        found.push(...(await axe(page, '.arch-layout')).map((v) => `[${view}] ${v}`));
      }
      expect(found).toEqual([]);
    });
  }
});

test.describe('axe overlays', () => {
  test.use({ viewport: { width: 911, height: 467 }, deviceScaleFactor: 1.5 });
  for (const theme of THEMES) {
    test(`help dialog and side menu drawer, ${theme}`, async ({ page }) => {
      await open(page, '#flow/obo', { theme });
      await page.keyboard.press('n');
      await expect(page.locator('#nav')).toBeVisible();
      const found = (await axe(page)).map((v) => `[drawer] ${v}`);
      await page.keyboard.press('Escape');
      await page.keyboard.press('Shift+?');
      await expect(page.locator('#helpModal')).toBeVisible();
      found.push(...(await axe(page)).map((v) => `[help] ${v}`));
      expect(found).toEqual([]);
    });
  }
});
