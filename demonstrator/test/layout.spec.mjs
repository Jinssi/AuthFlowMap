// Layout: every route at three screen and zoom combinations in both themes.
import { test, expect, open, go, layoutProblems, pillProblems, ROUTES, SIZES, THEMES, FLOWS } from './helpers.mjs';

// One page per size and theme walks every route through the side menu's hash links, one test step per route.
for (const size of SIZES) {
  test.describe(`layout ${size.name}`, () => {
    test.use({ viewport: { width: size.width, height: size.height }, deviceScaleFactor: size.scale });
    for (const theme of THEMES) {
      test(theme, async ({ page }) => {
        await open(page, ROUTES[0].hash, { theme });
        for (const r of ROUTES) {
          await test.step(r.hash, async () => {
            await go(page, r.hash);
            const problems = [...await layoutProblems(page)];
            if (r.kind === 'flow') {
              // Mid-flow, with the inspector filled in, in both diagram types.
              for (const view of ['diagram', 'sequence']) {
                await page.evaluate((v) => { APP.player.setView(v); APP.player.goTo(Math.floor(APP.player.steps.length / 2)); APP.player.syncLayout(); APP.player.zoom.apply(); }, view);
                problems.push(...(await layoutProblems(page)).map((p) => `${view}: ${p}`));
              }
              await page.evaluate(() => APP.player.setView('diagram'));
            }
            if (r.kind === 'architecture') {
              for (const view of ['bowtie', 'hub', 'columns']) {
                await page.locator(`#archTab-${view}`).click();
                problems.push(...(await layoutProblems(page)).map((p) => `${view}: ${p}`));
              }
            }
            expect.soft(problems, r.hash).toEqual([]);
          });
        }
      });
    }
  });
}

// In every layout each architecture node sits wholly inside a zone shape (column, wing, knot, slice or core) and the
// canvas, and no two nodes overlap. This also catches nodes placed below the canvas.
for (const view of ['columns', 'bowtie', 'hub']) {
  test(`architecture nodes stay inside their zones, ${view}`, async ({ page }) => {
    await open(page, '#architecture');
    await page.locator(`#archTab-${view}`).click();
    await expect(page.locator('#archSvg')).toHaveAttribute('data-view', view);
    const problems = await page.evaluate(() => {
      const svg = document.querySelector('#archSvg'), vb = svg.viewBox.baseVal, zones = [...svg.querySelectorAll('.zone-rect')];
      const boxes = [...svg.querySelectorAll('.node')].map((n) => {
        const m = n.transform.baseVal.consolidate().matrix, b = n.querySelector('.box').getBBox();
        return { id: n.dataset.actor, x: m.e, y: m.f, x2: m.e + b.width, y2: m.f + b.height };
      });
      return boxes.flatMap((a) => {
        const out = [], corners = [[a.x, a.y], [a.x2, a.y], [a.x, a.y2], [a.x2, a.y2]];
        if (a.x < 0 || a.y < 0 || a.x2 > vb.width || a.y2 > vb.height) out.push(`${a.id} at ${a.x},${a.y} is off the canvas`);
        if (!zones.some((z) => corners.every(([x, y]) => z.isPointInFill(new DOMPoint(x, y))))) out.push(`${a.id} at ${a.x},${a.y} is outside its zone`);
        for (const c of boxes) if (a.id < c.id && a.x < c.x2 && c.x < a.x2 && a.y < c.y2 && c.y < a.y2) out.push(`${a.id} overlaps ${c.id}`);
        return out;
      });
    });
    expect(problems).toEqual([]);
  });
}

// Labels are measured in SVG units, so one screen size covers them. Every step of every flow and variant, in both views.
test.describe('step labels', () => {
  for (const f of FLOWS.filter((x) => x.kind === 'flow')) {
    test(f.id, async ({ page }) => {
      await open(page, `#flow/${f.id}`);
      const problems = [];
      for (const variant of f.variants.length ? f.variants : [null]) {
        if (variant) {
          await page.evaluate(async (v) => { const r = document.querySelector(`input[name=variant][value="${v}"]`); r.checked = true; r.dispatchEvent(new Event('change')); }, variant);
          await page.waitForFunction(() => APP.player.idx === -1 && APP.player.steps.length > 0);
        }
        for (const view of ['diagram', 'sequence']) {
          await page.evaluate((v) => APP.player.setView(v), view);
          const n = await page.evaluate(() => APP.player.steps.length);
          for (let i = 0; i < n; i++) {
            await page.evaluate((k) => APP.player.goTo(k), i);
            problems.push(...(await pillProblems(page)).map((p) => `${variant || 'default'} ${view} step ${i + 1}: ${p}`));
          }
        }
      }
      expect(problems).toEqual([]);
    });
  }
});
