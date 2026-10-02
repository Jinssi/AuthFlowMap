// Checks every documentation URL in src/doc-links.js. Usage: node demonstrator/check-links.mjs
// A link fails when it returns an error status, redirects anywhere, or serves a "page not found" page with 200.
import { readFileSync } from 'node:fs';
const src = readFileSync(new URL('./src/doc-links.js', import.meta.url), 'utf8');
const urls = [...new Set([...src.matchAll(/'(https:\/\/[^']+)'/g)].map((m) => m[1]))];
const UA = { 'User-Agent': 'Mozilla/5.0 (AuthFlowMap link check)' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function check(u) {
  for (let attempt = 1; ; attempt++) {
    try {
      const r = await fetch(u, { redirect: 'manual', headers: UA, signal: AbortSignal.timeout(20000) });
      if ((r.status === 429 || r.status >= 500) && attempt < 3) { await sleep(1500 * attempt); continue; }
      if (r.status >= 300 && r.status < 400) return { ok: false, why: `${r.status} redirects to ${new URL(r.headers.get('location') || '', u)}` };
      if (r.status >= 400) return { ok: false, why: String(r.status) };
      const title = ((await r.text()).match(/<title[^>]*>([^<]*)<\/title>/i)?.[1] || '').trim();
      if (/\b404\b|page not found|not found/i.test(title)) return { ok: false, why: `200 but the page says "${title}"` };
      return { ok: true, why: `${r.status} ${title}` };
    } catch (e) {
      if (attempt < 3) { await sleep(1500 * attempt); continue; }
      return { ok: false, why: `network error: ${e.message}` };
    }
  }
}

let bad = 0;
const queue = [...urls];
const results = new Map();
await Promise.all(Array.from({ length: 6 }, async () => {
  while (queue.length) { const u = queue.shift(); results.set(u, await check(u)); }
}));
for (const u of urls) {
  const { ok, why } = results.get(u);
  if (!ok) bad++;
  console.log(`${ok ? 'ok ' : 'BAD'} ${u}  ${ok ? '' : why}`);
}
console.log(`${urls.length} links, ${bad} broken or redirected`);
process.exit(bad ? 1 : 0);
