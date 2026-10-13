// Renders cookbook/recipes/*.md into site/dist/ HTML with sidebar + TOC,
// replacing ```snippet:<path> fences with real snippet file contents and
// <!-- PROVENANCE --> comments with visible footers.
import { readFileSync, writeFileSync, mkdirSync, readdirSync, copyFileSync } from 'fs';
import { resolve, dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { marked } from 'marked';

const here = dirname(fileURLToPath(import.meta.url));
const cookbook = resolve(here, '..');
const repoRoot = resolve(cookbook, '..');
const dist = join(cookbook, 'site', 'dist');

function escapeHtml(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function frontmatterOf(text) {
  const match = text.match(/^---\n([\s\S]*?)\n---\n/);
  const data = {};
  if (match) {
    for (const line of match[1].split('\n')) {
      const [key, ...rest] = line.split(':');
      data[key.trim()] = rest.join(':').trim();
    }
  }
  return { meta: data, body: text.replace(/^---\n[\s\S]*?\n---\n/, '') };
}

function renderProse(body) {
  body = body.replace(/```snippet:(.+?)\n```/g, (full, path) => {
    const source = readFileSync(join(cookbook, 'snippets', path.trim()), 'utf8').trimEnd();
    const lang = path.trim().endsWith('.c') ? 'c' : 'js';
    return `\n\`\`\`${lang}\n${source}\n\`\`\`\n`;
  });
  const html = marked.parse(body);
  const withGaps = html.replace(
    /<blockquote>\s*<p>\[!WARNING\] GAP<\/p>([\s\S]*?)<\/blockquote>/g,
    (full, inner) =>
      `<div class="gap"><p><strong>GAP — not yet implemented</strong></p>${inner}</div>`);
  return withGaps.replace(/<!--\s*PROVENANCE([\s\S]*?)-->/g, (full, inner) =>
    `<footer class="provenance">PROVENANCE${inner}</footer>`);
}

const pages = readdirSync(join(cookbook, 'recipes')).sort()
  .filter(file => file.endsWith('.md'))
  .map(file => {
    const raw = readFileSync(join(cookbook, 'recipes', file), 'utf8');
    const { meta, body } = frontmatterOf(raw);
    return { file, meta, body };
  });
pages.sort((a, b) => (a.meta.number - b.meta.number));

const REQUIRED_META_KEYS = ['number', 'slug', 'title', 'section', 'status', 'maturity'];
for (const page of pages) {
  const missing = REQUIRED_META_KEYS.filter(key => !page.meta[key]);
  if (missing.length) {
    throw new Error(`recipe ${page.file}: missing frontmatter keys: ${missing.join(', ')}`);
  }
}

// --- cookbook hub index table ---
const statusBadge = status => `<span class="badge ${status}">${escapeHtml(status)}</span>`;
const indexTable = ['<table class="recipe-index">',
  '<tr><th>#</th><th>Recipe</th><th>Status</th><th>Maturity</th><th>Languages</th><th>Section</th></tr>'];
for (const page of pages) {
  const languages = (page.meta.languages || '').split(/\s+/).filter(Boolean).join(' · ');
  indexTable.push(
    `<tr><td>${escapeHtml(page.meta.number)}</td><td><a href="/cookbook/${escapeHtml(page.meta.slug)}/">${escapeHtml(page.meta.title)}</a></td><td>${statusBadge(page.meta.status)}</td><td>${escapeHtml(page.meta.maturity)}</td><td>${escapeHtml(languages)}</td><td>${escapeHtml(page.meta.section)}</td></tr>`);
}
indexTable.push('</table>');

// --- sidebar (shared across cookbook pages) ---
const BADGE_LABEL = { COMPLETE: 'COMP', PARTIAL: 'PART', UNSUPPORTED: 'GAP' };
const sidebarLinks = pages.map(page =>
  `<a href="/cookbook/${escapeHtml(page.meta.slug)}/">${String(page.meta.number).padStart(2, '0')} ${escapeHtml(page.meta.title)}<span class="badge ${page.meta.status}">${escapeHtml(BADGE_LABEL[page.meta.status] || '')}</span></a>`).join('\n');

function sidebarFor() {
  return `<div class="sidebar">
  <h1><a href="/">CRABS</a></h1>
  <p style="font-size:12px; margin: 4px 0 12px">Verified recipes.<br>Run in CI. Gaps stay visible.</p>
  <nav>${sidebarLinks}</nav>
</div>`;
}

// Collect h2/h3 into TOC entries and add matching ids to the page's headings.
function carveTableOfContents(mainHtml) {
  const entries = [];
  const html = mainHtml.replace(/<h([23])>([\s\S]*?)<\/h\1>/g, (full, level, text) => {
    const headingId = `heading-${entries.length}`;
    entries.push({ level, headingId, text: text.replace(/<[^>]+>/g, '') });
    return `<h${level} id="${headingId}">${text}</h${level}>`;
  });
  const tocHtml = entries.length < 2 ? '' :
    `<div class="toc">${entries.map(entry =>
      `<a class="toc-${entry.level}" href="#${entry.headingId}">${entry.text}</a>`).join('\n')}</div>`;
  return { html, tocHtml };
}

function pageShell({ title, mainHtml }) {
  const { html, tocHtml } = carveTableOfContents(mainHtml);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body><div class="layout">${sidebarFor()}
<div class="main">${html}</div>
${tocHtml}
</div></body></html>`;
}

// --- emit pages ---
mkdirSync(join(dist, 'assets'), { recursive: true });
mkdirSync(join(dist, 'cookbook'), { recursive: true });
copyFileSync(join(repoRoot, 'Encryptstacean.png'), join(dist, 'assets', 'Encryptstacean.png'));
copyFileSync(join(repoRoot, 'Unlockster.png'), join(dist, 'assets', 'Unlockster.png'));
copyFileSync(join(cookbook, 'site', 'assets', 'style.css'), join(dist, 'assets', 'style.css'));

// --- wasm bundles for the interactive demo panels ---
// The Emscripten glue (crabs.dev.js / crabs.js) resolves its .wasm binary via
// locateFile relative to its own script URL, so each pair is served
// side-by-side from assets/wasm/; bindings-core.js maps the glue factory onto
// the high-level Node/KeyPair API in the browser (see panel.js).
mkdirSync(join(dist, 'assets', 'wasm'), { recursive: true });
const WASM_ASSETS = ['crabs.dev.js', 'crabs.dev.wasm', 'crabs.js', 'crabs.wasm', 'bindings-core.js'];
for (const wasmAsset of WASM_ASSETS) {
  copyFileSync(join(repoRoot, 'bindings', 'wasm', wasmAsset), join(dist, 'assets', 'wasm', wasmAsset));
}
writeFileSync(join(dist, 'index.html'), readFileSync(join(cookbook, 'site', 'index.html')));

writeFileSync(join(dist, 'cookbook', 'index.html'), pageShell({
  title: 'The CRABS Cookbook',
  mainHtml: `<h1>The CRABS Cookbook</h1><p>Fifteen recipes with runnable code, plus one honest gap page. STATUS and
  maturity badges are honest: PARTIAL means gaps are documented on the page.
  UNSUPPORTED means the codebase cannot deliver it yet.</p>${indexTable.join('\n')}
  <div class="callout"><img src="/assets/Unlockster.png"><p>Trust caveat: recipes
  only claim what the code proves today. DESIGNED symbols never appear in
  COMPLETE recipes.</p></div>`,
}));

for (const page of pages) {
  const outDir = join(dist, 'cookbook', page.meta.slug);
  mkdirSync(outDir, { recursive: true });
  writeFileSync(join(outDir, 'index.html'), pageShell({
    title: `${escapeHtml(page.meta.number)} — ${escapeHtml(page.meta.title)} — CRABS Cookbook`,
    mainHtml: renderProse(page.body),
  }));
}

// --- interactive demo panels (recipes that opt in via `interactive: true`) ---
// Each interactive recipe names its demo page as site/interactive/<file base>.html;
// the shared panel.js (wasm boot + action wiring) is copied once.
const interactivePages = pages.filter(page => page.meta.interactive === 'true');
if (interactivePages.length) {
  copyFileSync(join(cookbook, 'site', 'interactive', 'panel.js'), join(dist, 'assets', 'panel.js'));
  for (const page of interactivePages) {
    const demoSource = join(cookbook, 'site', 'interactive', page.file.replace(/\.md$/, '.html'));
    copyFileSync(demoSource, join(dist, 'cookbook', page.meta.slug, 'interactive.html'));
  }
}
console.log(`Built ${pages.length} recipe pages into ${dist}`);