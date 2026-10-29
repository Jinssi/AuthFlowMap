// Keyboard, focus, zoom, drawer and presenter behaviour with real input events.
import { test, expect, open } from './helpers.mjs';

const focusedId = (page) => page.evaluate(() => document.activeElement?.id || document.activeElement?.className || document.activeElement?.tagName);

test.describe('keyboard and focus', () => {
  test.use({ viewport: { width: 1920, height: 1000 } });

  test('skip link moves focus to the main content', async ({ page }) => {
    await open(page, '#architecture');
    await page.keyboard.press('Tab');
    await expect(page.locator('#skipLink')).toBeFocused();
    await page.keyboard.press('Enter');
    expect(await focusedId(page)).toBe('main');
  });

  test('space plays, arrows step, R resets, V switches the view', async ({ page }) => {
    await open(page, '#flow/obo');
    await page.locator('#main h1').click();
    await page.keyboard.press('ArrowRight');
    await page.keyboard.press('ArrowRight');
    await expect(page.locator('.step-item[aria-current="step"]')).toHaveAttribute('data-i', '1');
    await page.keyboard.press('ArrowLeft');
    await expect(page.locator('.step-item[aria-current="step"]')).toHaveAttribute('data-i', '0');
    await page.keyboard.press('v');
    await expect(page.locator('[data-view="sequence"]')).toHaveAttribute('aria-pressed', 'true');
    await page.keyboard.press('r');
    await expect(page.locator('.step-item[aria-current="step"]')).toHaveCount(0);
    await page.keyboard.press(' ');
    await expect(page.locator('#btnPlay')).toContainText(/Pause/);
    await page.keyboard.press(' ');
    await expect(page.locator('#btnPlay')).toContainText(/Resume/);
  });

  test('inspector tabs keep focus and follow the arrow keys', async ({ page }) => {
    await open(page, '#flow/obo');
    // Step to the first hop that carries an HTTP request, so the Request tab is enabled.
    await page.evaluate(() => { for (let i = 0; i < APP.player.steps.length; i++) { APP.player.goTo(i); if (!document.querySelector('#itab-request').disabled) return; } });
    await page.locator('#itab-request').click();
    await expect(page.locator('#itab-request')).toBeFocused();
    await expect(page.locator('#itab-request')).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('ArrowRight');
    // Disabled tabs are skipped and the arrows wrap around.
    const next = await page.evaluate(() => { const t = [...document.querySelectorAll('.insp-tabs [role=tab]')].filter((b) => !b.disabled); return t[(t.findIndex((b) => b.id === 'itab-request') + 1) % t.length].id; });
    await expect(page.locator(`#${next}`)).toBeFocused();
    await expect(page.locator(`#${next}`)).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('Home');
    await expect(page.locator('#itab-overview')).toBeFocused();
  });

  test('diagram components are keyboard reachable', async ({ page }) => {
    await open(page, '#architecture');
    const nodes = page.locator('#archSvg .node[tabindex="0"]');
    expect(await nodes.count()).toBeGreaterThan(20);
    await nodes.first().focus();
    const name = (await nodes.first().locator('text.name').textContent()).trim();
    await page.keyboard.press('Enter');
    await expect(page.locator('#archSide')).toContainText(name);
  });

  test('architecture layout tabs follow the arrow keys and are remembered', async ({ page }) => {
    await open(page, '#architecture');
    const svg = page.locator('#archSvg');
    await expect(svg).toHaveAttribute('data-view', 'columns');
    await page.locator('#archTab-columns').focus();
    await page.keyboard.press('ArrowRight');
    await expect(page.locator('#archTab-bowtie')).toBeFocused();
    await expect(page.locator('#archTab-bowtie')).toHaveAttribute('aria-selected', 'true');
    await expect(svg).toHaveAttribute('data-view', 'bowtie');
    await page.keyboard.press('End');
    await expect(svg).toHaveAttribute('data-view', 'hub');
    await expect(page.locator('#archVp')).toHaveAttribute('aria-labelledby', 'archTab-hub');
    await page.reload();
    await expect(page.locator('#archSvg')).toHaveAttribute('data-view', 'hub');
    await expect(page.locator('#archTab-hub')).toHaveAttribute('aria-selected', 'true');
  });

  test('selecting a component highlights only its connections', async ({ page }) => {
    await open(page, '#architecture');
    await page.locator('#archTab-hub').click();
    const svg = page.locator('#archSvg');
    await page.locator('#archSvg .node[data-actor="graph"]').click();
    await expect(svg).toHaveClass(/has-sel/);
    await expect(page.locator('#archSvg .node[data-actor="graph"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#archSide h2')).toContainText('Microsoft Graph');
    const hl = await page.locator('#archSvg .arch-edge.hl').count();
    expect(hl).toBeGreaterThan(2);
    // Every highlighted edge touches the selected component.
    expect(await page.evaluate(() => [...document.querySelectorAll('#archSvg .arch-edge.hl')].every((e) => [e.dataset.a, e.dataset.b].includes('graph')))).toBe(true);
  });

  test('the architecture layouts share one zoom level', async ({ page }) => {
    await open(page, '#architecture');
    await page.locator('.arch-tools [data-z="one"]').click();
    const val = page.locator('.arch-tools .zb-val');
    await expect(val).toHaveText('100%');
    await page.locator('.arch-tools [data-z="out"]').click();
    const zoomed = await val.textContent();
    for (const view of ['bowtie', 'hub', 'columns']) {
      await page.locator(`#archTab-${view}`).click();
      await expect(val, view).toHaveText(zoomed);
    }
  });

  test('help dialog opens with ?, traps focus and returns it on Esc', async ({ page }) => {
    await open(page, '#flow/obo');
    await page.locator('#helpBtn').focus();
    await page.keyboard.press('Shift+?');
    const dlg = page.locator('#helpModal');
    await expect(dlg).toBeVisible();
    // A native modal dialog makes the page inert: Tab moves between the dialog and the browser's own UI (body here), never the page.
    const seen = new Set();
    for (let i = 0; i < 8; i++) {
      await page.keyboard.press('Tab');
      const where = await page.evaluate(() => { const a = document.activeElement; return a.closest('#helpModal') ? `dialog:${a.id || a.tagName}` : a === document.body ? 'browser' : `page:${a.id || a.className || a.tagName}`; });
      expect(where).not.toMatch(/^page:/);
      seen.add(where);
    }
    expect(seen).toContain('dialog:helpClose');
    await page.keyboard.press('Escape');
    await expect(dlg).toBeHidden();
    await expect(page.locator('#helpBtn')).toBeFocused();
  });

  test('help dialog fits a small zoomed window and can be closed', async ({ page }) => {
    await page.setViewportSize({ width: 911, height: 467 });
    await open(page, '#architecture');
    await page.locator('#helpBtn').click();
    const close = page.locator('#helpModal button', { hasText: /close/i }).last();
    await close.scrollIntoViewIfNeeded();
    await expect(close).toBeInViewport();
    await close.click();
    await expect(page.locator('#helpModal')).toBeHidden();
  });
});

test.describe('side menu', () => {
  test('docks on a wide screen and hides with N', async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1000 });
    await open(page, '#architecture');
    const btn = page.locator('#navBtn');
    await expect(page.locator('#nav')).toBeVisible();
    await expect(btn).toHaveAttribute('aria-expanded', 'true');
    await page.locator('#main h1').click();
    await page.keyboard.press('n');
    await expect(page.locator('#nav')).toBeHidden();
    await expect(btn).toHaveAttribute('aria-expanded', 'false');
  });

  test('becomes a drawer on a zoomed laptop', async ({ page }) => {
    await page.setViewportSize({ width: 911, height: 467 });
    await open(page, '#flow/obo');
    const nav = page.locator('#nav'), btn = page.locator('#navBtn');
    await expect(nav).toBeHidden();
    await btn.click();
    await expect(nav).toBeVisible();
    await expect(btn).toHaveAttribute('aria-expanded', 'true');
    expect(await page.evaluate(() => !!document.activeElement.closest('#nav'))).toBe(true);
    await page.keyboard.press('Escape');
    await expect(nav).toBeHidden();
    await expect(btn).toBeFocused();
    // The scrim closes it, and so does picking a page.
    await btn.click();
    await page.mouse.click(880, 300);
    await expect(nav).toBeHidden();
    await btn.click();
    await nav.locator('a[href="#architecture"]').click();
    await expect(nav).toBeHidden();
    await expect(page).toHaveTitle(/Architecture/);
  });
});

test.describe('diagram zoom', () => {
  test.use({ viewport: { width: 1280, height: 667 } });

  test('buttons and keys zoom, 0 fits, and the level survives a reload', async ({ page }) => {
    await open(page, '#flow/obo');
    const val = page.locator('#main .zb-val');
    const fit = await val.textContent();
    await page.locator('[data-z="in"]').click();
    await expect(val).not.toHaveText(fit);
    await expect(page.locator('[data-z="fit"]')).toHaveAttribute('aria-pressed', 'false');
    await page.locator('[data-z="one"]').click();
    await expect(val).toHaveText('100%');
    await page.locator('#main h1').click();
    await page.keyboard.press('+');
    await expect(val).toHaveText('125%');
    await page.reload();
    await page.waitForFunction(() => document.querySelectorAll('.step-item').length > 0);
    await expect(page.locator('#main .zb-val')).toHaveText('125%');
    await page.locator('#main h1').click();
    await page.keyboard.press('0');
    await expect(page.locator('[data-z="fit"]')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('#main .zb-val')).toHaveText(fit);
  });

  test('Ctrl+wheel zooms and dragging pans without clicking a component', async ({ page }) => {
    await open(page, '#flow/obo');
    await page.locator('[data-z="one"]').click();
    await page.locator('[data-z="in"]').click();
    await page.locator('[data-z="in"]').click();
    const vp = page.locator('#stageView');
    await expect(vp).toHaveClass(/pannable/);
    await expect(vp).toHaveAttribute('tabindex', '0');
    const box = await vp.boundingBox();
    const cx = box.x + box.width / 2, cy = box.y + box.height / 2;
    const before = await vp.evaluate((v) => [v.scrollLeft, v.scrollTop]);
    await page.evaluate(() => { window.__nodeClicks = 0; document.querySelectorAll('#stageView .node').forEach((n) => n.addEventListener('click', () => window.__nodeClicks++)); });
    await page.mouse.move(cx, cy);
    await page.mouse.down();
    await page.mouse.move(cx - 150, cy - 60, { steps: 8 });
    await page.mouse.up();
    const after = await vp.evaluate((v) => [v.scrollLeft, v.scrollTop]);
    expect(after[0]).toBeGreaterThan(before[0]);
    expect(await page.evaluate(() => window.__nodeClicks)).toBe(0);
    const s0 = await page.evaluate(() => APP.player.zoom.scale);
    await page.keyboard.down('Control');
    await page.mouse.wheel(0, -300);
    await page.keyboard.up('Control');
    await expect.poll(() => page.evaluate(() => APP.player.zoom.scale)).toBeGreaterThan(s0);
  });

  test('fit never draws component names smaller than 12px', async ({ page }) => {
    await page.setViewportSize({ width: 911, height: 467 });
    await open(page, '#flow/multi-agent');
    const k = await page.evaluate(() => { const s = document.querySelector('#stageView .stage-svg'); return s.getBoundingClientRect().width / s.viewBox.baseVal.width; });
    expect(k * 14).toBeGreaterThanOrEqual(11.9);
  });
});

test.describe('presenter mode', () => {
  test.use({ viewport: { width: 1920, height: 1000 } });

  test('P enlarges the diagram and hides the side menu and briefing, Esc leaves', async ({ page }) => {
    await open(page, '#flow/obo');
    const scale = () => page.evaluate(() => APP.player.zoom.scale);
    await page.locator('#main h1').click();
    await page.keyboard.press('p');
    await expect(page.locator('#btnPresent')).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.briefing')).toBeHidden();
    await expect(page.locator('#nav')).toBeHidden();
    expect(await scale() * 14).toBeGreaterThanOrEqual(15.9);
    await page.keyboard.press('Escape');
    await expect(page.locator('#btnPresent')).toHaveAttribute('aria-pressed', 'false');
    await expect(page.locator('.briefing')).toBeVisible();
    await expect(page.locator('#nav')).toBeVisible();
  });
});

test.describe('sequence view', () => {
  test.use({ viewport: { width: 911, height: 467 }, deviceScaleFactor: 1.5 });

  test('component header stays put while the diagram scrolls', async ({ page }) => {
    await open(page, '#flow/multi-agent');
    await page.locator('[data-view="sequence"]').click();
    const vp = page.locator('#stageView');
    await vp.evaluate((v) => { v.scrollTop = 250; v.scrollLeft = 120; });
    const r = await page.evaluate(() => {
      const v = document.querySelector('#stageView'), h = v.querySelector('.seq-sticky svg'), b = v.querySelector('.stage-svg');
      return { headTop: h.getBoundingClientRect().top - v.getBoundingClientRect().top, dx: h.getBoundingClientRect().left - b.getBoundingClientRect().left };
    });
    expect(Math.abs(r.headTop)).toBeLessThan(1);
    expect(Math.abs(r.dx)).toBeLessThan(1);
  });
});

test.describe('reduced motion', () => {
  test.use({ viewport: { width: 1920, height: 1000 }, reducedMotion: 'reduce' });

  test('a whole flow plays to the end', async ({ page }) => {
    await open(page, '#flow/client-credentials');
    await page.evaluate(() => { APP.speed = 8; });
    await page.locator('#btnPlay').click();
    await expect(page.locator('#btnFwd')).toBeDisabled({ timeout: 20000 });
    await expect.poll(() => page.evaluate(() => APP.player.finished), { timeout: 10000 }).toBe(true);
  });
});
