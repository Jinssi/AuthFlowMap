// Shared fixtures for the demonstrator UI suite. Dev-only: index.html itself stays dependency-free.
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { test as base, expect } from '@playwright/test';

const SRC = fileURLToPath(new URL('../src/', import.meta.url));
export const INDEX = pathToFileURL(fileURLToPath(new URL('../index.html', import.meta.url))).href;

/** Every flow, read from the same data files build.mjs inlines (its script list up to reference.js), so a new flow is tested without editing this suite. */
function loadFlows() {
  const list = readFileSync(new URL('../build.mjs', import.meta.url), 'utf8').match(/const scripts = \[([^\]]+)\]/)[1];
  const all = [...list.matchAll(/'([^']+)'/g)].map((m) => m[1]);
  const files = all.slice(0, all.indexOf('reference.js'));
  const code = `${files.map((f) => readFileSync(SRC + f, 'utf8')).join('\n;\n')}\n;FLOWS.map((f) => ({ id: f.id, title: f.title, kind: f.kind || 'flow', variants: (f.variants || []).map((v) => v.id) }))`;
  return vm.runInNewContext(code, { console });
}
export const FLOWS = loadFlows();
export const ROUTES = [
  { hash: '#architecture', kind: 'architecture' },
  ...FLOWS.map((f) => ({ hash: `#flow/${f.id}`, kind: f.kind, flow: f })),
  { hash: '#reference', kind: 'reference' },
  { hash: '#reference/docs', kind: 'reference' },
];

/** CSS viewport and device scale for common screens at the browser zoom people actually use. */
export const SIZES = [
  { name: 'FHD 100%', width: 1920, height: 1000, scale: 1 },
  { name: 'laptop 150%', width: 911, height: 467, scale: 1.5 },
  { name: 'FHD 200%', width: 960, height: 500, scale: 2 },
];
export const THEMES = ['dark', 'light'];

/** A page fixture that fails the test on any uncaught error or console error. */
export const test = base.extend({
  page: async ({ page }, use) => {
    const errors = [];
    page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
    page.on('console', (m) => { if (m.type() === 'error') errors.push(`console: ${m.text()}`); });
    await use(page);
    expect(errors, 'browser errors').toEqual([]);
  },
});
export { expect };

/** Open a route and wait until it has rendered (flows also need their async simulated run context). */
export async function open(page, hash, { theme = 'dark' } = {}) {
  await page.goto(`${INDEX}?theme=${theme}${hash}`);
  await rendered(page, hash);
}

/** Switch route inside the already open page, the way the side menu does, which is much cheaper than a reload. */
export async function go(page, hash) {
  await page.evaluate((h) => { location.hash = h; }, hash);
  await rendered(page, hash);
}

function rendered(page, hash) {
  return page.waitForFunction((h) => {
    // Deep-link options after "?" aren't part of the route.
    h = h.split('?')[0];
    if (APP.route !== h || !document.querySelector('#main h1')) return false;
    if (h.startsWith('#flow/') && document.querySelector('#stageView')) return document.querySelectorAll('.step-item').length > 0;
    return true;
  }, hash);
}

/** Layout probe run inside the page. Returns a list of human-readable problems, empty when the page is clean. */
export function layoutProblems(page) {
  return page.evaluate(() => {
    const out = [];
    const de = document.documentElement;
    if (de.scrollWidth > innerWidth + 1) out.push(`page scrolls sideways by ${de.scrollWidth - innerWidth}px`);
    for (const sel of ['.topbar', 'main', '.controls', '.stage-top']) {
      const el = document.querySelector(sel);
      if (el && el.scrollWidth > el.clientWidth + 1) out.push(`${sel} overflows sideways by ${el.scrollWidth - el.clientWidth}px`);
    }
    // Diagram text has to stay readable: one SVG unit is drawn at (rendered width / viewBox width) CSS px.
    document.querySelectorAll('svg.zsvg').forEach((svg) => {
      const vb = svg.viewBox.baseVal; const r = svg.getBoundingClientRect();
      if (!vb.width || !r.width) return;
      const k = r.width / vb.width;
      svg.querySelectorAll('.node text.name').forEach((t) => {
        const px = parseFloat(getComputedStyle(t).fontSize) * k;
        if (px < 11.9) out.push(`"${t.textContent}" is drawn at ${px.toFixed(1)}px`);
      });
    });
    // Node names and roles must stay inside the 124-unit text area of the 220-unit node.
    // Glyph overhang can poke a unit or two past the measured advance width.
    document.querySelectorAll('.zsvg .node').forEach((g) => {
      g.querySelectorAll('text.name, text.role').forEach((t) => {
        const b = t.getBBox();
        if (b.width && b.x + b.width > 44 + 124 + 2) out.push(`node text "${t.textContent}" overflows its node`);
      });
    });
    document.querySelectorAll('.zsvg [data-max]').forEach((t) => {
      if (t.getComputedTextLength() > Number(t.dataset.max) + 0.5) out.push(`label "${t.textContent}" is wider than its ${t.dataset.max} limit`);
    });
    // The sticky inspector must never slide under the controls bar.
    const ins = document.querySelector('.inspector'), ctl = document.querySelector('.controls');
    if (ins && ctl) {
      const a = ins.getBoundingClientRect(), b = ctl.getBoundingClientRect();
      if (a.top < b.bottom - 1 && a.bottom > b.top + 1 && a.left < b.right && a.right > b.left) out.push('the inspector overlaps the controls bar');
    }
    return out;
  });
}

/** Pills drawn around SVG text: the edge label on the active hop and the packet label. */
export function pillProblems(page) {
  return page.evaluate(() => {
    const out = [];
    for (const [g, pad] of [['#edgeLbl', 0], ['#packet g', 0]]) {
      const grp = document.querySelector(`#stageView ${g}`);
      if (!grp || grp.closest('[style*="display: none"], [style*="display:none"]')) continue;
      const rect = grp.querySelector('rect'), text = grp.querySelector('text');
      if (!rect || !text || !text.textContent) continue;
      const rb = rect.getBBox(), tb = text.getBBox();
      if (tb.x < rb.x - 0.5 + pad || tb.x + tb.width > rb.x + rb.width + 0.5 - pad) out.push(`"${text.textContent}" spills out of its pill (${tb.width.toFixed(0)} > ${rb.width.toFixed(0)})`);
    }
    return out;
  });
}
