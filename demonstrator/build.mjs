// Inlines demonstrator/src/* into a single self-contained demonstrator/index.html (no dependencies).
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = (f) => readFileSync(join(here, 'src', f), 'utf8');

const scripts = ['config.js', 'actors.js', 'flows-standard.js', 'flows-standard2.js', 'flows-standard3.js', 'casim-data.js', 'flows-access1.js', 'flows-access2.js', 'flows-access3.js', 'flows-access4.js', 'flows-agent.js', 'flows-mcp.js', 'reference.js', 'reference-access.js', 'engine.js', 'player.js', 'casim.js', 'casim-live.js', 'live.js', 'app.js'];
const guard = (s) => s.replace(/<\/script/gi, '<\\/script');

let html = src('template.html')
  .replace('/*__CSS__*/', () => src('styles.css'))
  .replace('/*__JS__*/', () => scripts.map((f) => `// ---- ${f} ----\n${guard(src(f))}`).join('\n\n'));

writeFileSync(join(here, 'index.html'), html);
console.log(`Built demonstrator/index.html (${(html.length / 1024).toFixed(1)} KB)`);
