// Checks every documentation URL in src/doc-links.js. Usage: node demonstrator/check-links.mjs
import { readFileSync } from 'node:fs';
const src = readFileSync(new URL('./src/doc-links.js', import.meta.url), 'utf8');
const urls = [...new Set([...src.matchAll(/'(https:\/\/[^']+)'/g)].map((m) => m[1]))];
let bad = 0;
for (const u of urls) {
  try {
    const r = await fetch(u, { redirect: 'follow', headers: { 'User-Agent': 'Mozilla/5.0 link-check' } });
    const ok = r.status < 400;
    if (!ok) bad++;
    console.log(`${ok ? 'ok ' : 'BAD'} ${r.status} ${u}${r.url !== u ? `  ->  ${r.url}` : ''}`);
  } catch (e) { bad++; console.log(`ERR ${u} ${e.message}`); }
}
console.log(`${urls.length} links, ${bad} broken`);
process.exit(bad ? 1 : 0);
