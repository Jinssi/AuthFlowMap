// Inlines demonstrator/src/* into a single self-contained demonstrator/index.html (no dependencies).
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = (f) => readFileSync(join(here, 'src', f), 'utf8');

const scripts = ['config.js', 'actors.js', 'flows-standard.js', 'flows-webapp.js', 'flows-standard2.js', 'flows-standard3.js', 'casim-data.js', 'flows-access1.js', 'flows-access2.js', 'flows-access3.js', 'flows-access4.js', 'flows-agent.js', 'flows-mcp.js', 'flows-iq.js', 'flows-gsa1.js', 'flows-gsa2.js', 'reference.js', 'reference-access.js', 'reference-iq.js', 'reference-gsa.js', 'learn.js', 'doc-links.js', 'engine.js', 'player.js', 'casim.js', 'casim-live.js', 'live.js', 'arch.js', 'app.js'];
const guard = (s) => s.replace(/<\/script/gi, '<\\/script');

let html = src('template.html')
  .replace('/*__CSS__*/', () => src('styles.css'))
  .replace('/*__JS__*/', () => scripts.map((f) => `// ---- ${f} ----\n${guard(src(f))}`).join('\n\n'));

const out = join(here, 'index.html');
if (process.argv.includes('--check')) {
  // CI guard: fail when the committed index.html was not rebuilt after a source change.
  const norm = (s) => s.replace(/\r\n/g, '\n');
  if (norm(readFileSync(out, 'utf8')) !== norm(html)) {
    console.error('demonstrator/index.html is out of date. Run npm run build and commit the result.');
    process.exit(1);
  }
  console.log('demonstrator/index.html matches the sources');
} else {
  writeFileSync(out, html);
  console.log(`Built demonstrator/index.html (${(html.length / 1024).toFixed(1)} KB)`);
}
