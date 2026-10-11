# CRABS Cookbook GitHub Pages Site — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a GitHub Pages site (`/` landing page + `/cookbook/` section) hosting 16 verified CRABS recipes with runnable C, JS-wasm, and JS-node snippets that are actually executed by test harnesses wired into CI.

**Architecture:** Every code block shown on the site lives as a real executable file under `cookbook/snippets/{c,wasm,node}/`, executed by three harnesses (node script, C compile-and-run, Playwright browser). A dependency-light Node build script (`cookbook/site/build.mjs`) renders recipe markdown to HTML and injects snippet file contents at build time, so the site cannot drift from the tests. GitHub Actions runs the harnesses then deploys `cookbook/site/dist/` to Pages.

**Tech Stack:** Node ≥ 20 (build script, snippet runner), `marked` (markdown→HTML), Playwright (browser tests), CMake + cc (C harness), the committed wasm artifacts in `bindings/wasm/`, the compiled N-API addon from `bindings/node/`, GitHub Pages via the official `actions/deploy-pages` flow.

**Spec:** `docs/superpowers/specs/2026-10-11-cookbook-pages-site-design.md`

**Palette (from spec, locked):** bg `#F5CE89`, ink `#3A3325`, crab orange `#E0901F`, steel blue `#76A5E6`, baby blue `#BBD9EE`, code text `#111111`.

---

## File Structure

```
cookbook/
  api-map.md                      API MAP from recon (symbols, file:line, maturity)
  package.json                    devDeps: marked, playwright
  recipes/NN-slug.md              16 recipes (+ recipe-8b gap page)
  snippets/c/NN-slug.c            real compiled/run code = what the site shows
  prelude/c/prelude.h             shared C scaffold
  snippets/node/NN-slug.js
  snippets/wasm/NN-slug.js
  tests/run-snippets.mjs          executes all node+wasm snippets
  tests/run-c.sh                  cmake build + compile/run all C snippets
  tests/browser.js                Playwright: serve dist, drive interactive pages
  site/build.mjs                  markdown recipes → site/dist (snippet injection)
  site/index.html                 landing page (hand-written, copied to dist)
  site/assets/style.css           locked palette + layout
  site/assets/head.html           shared <head> fragment (fonts, highlight.js)
  site/dist/                      build output (gitignored)
bindings/wasm/crabs.js|crabs.wasm|crabs.dev.js|crabs.dev.wasm   committed artifacts
.github/workflows/cookbook-site.yml              test + deploy Pages on master
```

**Responsibilities:** `build.mjs` owns rendering + snippet injection + provenance rendering. `run-snippets.mjs` owns JS snippet execution honesty. `run-c.sh` owns C compile/run honesty. `browser.js` owns live in-browser proof. Recipes prose/structure live in `recipes/*.md`; snippet *content* lives only in `snippets/`.

**Repo conventions to honor (CLAUDE.md / STYLE_GUIDE):** no Co-Authored-By lines; conventional commits; C code per `docs/STYLE_GUIDE.md`; no single-letter variable names. JS snippet variables mirror names used in `bindings/wasm/test/*.js` (e.g. `node`, `key`, `op`).

**Recipe markdown contract (all recipe files):** frontmatter block, then sections. Author prose is *ours now* (we are author + editor), but the cookbook.md protocol still governs code: every symbol cited to `api-map.md`, provenance footer after each snippet block, GAP REPORT instead of invented API, honest STATUS lines.

Recipe frontmatter (parsed by `build.mjs`):

```yaml
---
number: 1
slug: shared-count
title: A shared count that can't be double-counted
section: Basics
status: COMPLETE        # COMPLETE | PARTIAL | UNSUPPORTED
maturity: STABLE        # STABLE | contains PRESENT | contains DESIGNED
target: crabs-wasm
languages: c wasm node  # surfaces this recipe actually delivers
---
```

Snippet injection: a recipe md block like

````markdown
```snippet:c/01-shared-count.c
```
````

is replaced by `<pre><code class="language-c">…file content…</code></pre>` plus a rendered provenance box from the HTML comment that follows it. Provenance comments use exactly the `docs/cookbook.md` footer shape (HTML comment block starting `<!-- PROVENANCE` with `target:`, `verified:`, `symbols:`, `maturity:`, `test_ref:` lines); `build.mjs` turns them into a visible `<footer class="provenance">` box.

---

### Task 1: Scaffold — package.json, palette CSS, landing page

**Files:**
- Create: `cookbook/package.json`
- Create: `cookbook/site/assets/style.css`
- Create: `cookbook/site/index.html`
- Create: `cookbook/.gitignore` (`node_modules/`, `site/dist/`)

- [ ] **Step 1: Create `cookbook/package.json`**

```json
{
  "name": "crabs-cookbook",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "build": "node site/build.mjs",
    "test:snippets": "node tests/run-snippets.mjs",
    "test:c": "bash tests/run-c.sh",
    "test:browser": "node tests/browser.js",
    "test": "npm run test:snippets && npm run test:c && npm run test:browser"
  },
  "devDependencies": {
    "marked": "^14.0.0",
    "playwright": "^1.47.0"
  }
}
```

- [ ] **Step 2: Install deps:** `cd cookbook && npm install` (expect `node_modules/` created, no errors).

- [ ] **Step 3: Write `cookbook/site/assets/style.css`** (complete file):

```css
:root {
  --bg: #F5CE89;
  --ink: #3A3325;
  --crab: #E0901F;
  --steel: #76A5E6;
  --baby: #BBD9EE;
  --code-text: #111111;
  --panel: #FFF7E6;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font: 16px/1.65 Georgia, 'Times New Roman', serif;
  background: var(--bg);
  color: var(--ink);
}
.layout { display: grid; grid-template-columns: 260px minmax(0, 1fr);
          grid-template-areas: "sidebar main"; }
.sidebar {
  grid-area: sidebar; padding: 24px 16px; border-right: 3px solid var(--steel);
  background: #FBDFBA; position: sticky; top: 0;
  height: 100vh; overflow-y: auto;
}
.sidebar h1 a { color: var(--crab); text-decoration: none; font-size: 24px; }
.sidebar nav a { display: block; padding: 4px 8px; margin: 2px 0; color: var(--ink);
                 text-decoration: none; border-radius: 6px; font-size: 14px; }
.sidebar nav a.active { background: var(--crab); color: #fff; }
.sidebar nav .badge { float: right; font-size: 11px; padding: 0 6px;
                      border-radius: 999px; background: var(--baby); color: var(--ink); }
.sidebar nav .badge.PARTIAL { background: var(--crab); color: #fff; }
.sidebar nav .badge.UNSUPPORTED { background: #8a6d3b; color: #fff; }
.main { grid-area: main; max-width: 860px; padding: 32px 40px; }
h1, h2, h3 { font-family: 'Segoe UI', system-ui, sans-serif; color: var(--crab); }
a { color: #B36A00; }
.toc { border-left: 3px solid var(--baby); padding-left: 14px; font-size: 14px;
       position: fixed; left: calc(50% + 430px); top: 40px; max-width: 220px; }
.toc a { color: #3E6BC0; text-decoration: none; display: block; }
pre {
  background: var(--baby); border: 2px solid var(--steel); border-radius: 10px;
  padding: 14px 16px; overflow-x: auto;
}
pre code, code { font: 14px/1.5 'Cascadia Code', Consolas, monospace;
                 color: var(--code-text); }
code { background: rgba(187, 217, 238, 0.5); padding: 1px 5px; border-radius: 4px; }
pre code { background: none; }
footer.provenance {
  background: var(--baby); border: 1px dashed var(--steel); border-radius: 8px;
  padding: 10px 14px; margin: 10px 0 24px; font: 12px/1.5 'Segoe UI', system-ui, sans-serif;
  white-space: pre-wrap; color: #1F3B6E;
}
.gap { background: var(--baby); border: 2px solid #8a6d3b; border-radius: 10px;
       padding: 12px 16px; margin: 16px 0; }
.gap strong { color: #8a6d3b; }
.landing { max-width: 900px; margin: 0 auto; padding: 40px 24px; }
.landing .hero { display: flex; gap: 32px; align-items: center; }
.landing .hero img { width: 300px; height: auto; }
.section-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
                 gap: 20px; margin-top: 32px; }
.section-cards .card { background: var(--panel); border: 2px solid var(--steel);
                       border-radius: 12px; padding: 20px; }
.section-cards .card h2 { margin-top: 0; }
.callout { display: flex; gap: 16px; align-items: center; background: var(--baby);
           border-radius: 12px; padding: 14px 20px; margin: 24px 0; }
.callout img { width: 90px; height: auto; }
table.recipe-index { border-collapse: collapse; width: 100%; }
table.recipe-index th, table.recipe-index td { padding: 8px 10px;
  border-bottom: 1px solid rgba(58, 51, 37, 0.25); text-align: left; }
table.recipe-index a { text-decoration: none; }
.interactive { background: #fff; border: 2px solid var(--steel); border-radius: 12px;
               padding: 16px; margin: 20px 0; }
.interactive button { background: var(--crab); color: #fff; border: none;
  padding: 8px 16px; border-radius: 999px; font-weight: 600; cursor: pointer;
  margin-right: 8px; }
.interactive pre { border: none; margin: 8px 0 0; }
```

- [ ] **Step 4: Write `cookbook/site/index.html`** (landing page — hero, CRABS summary, section cards linking to `/cookbook/`, mascots):

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CRABS — Cryptographic Attribute-Based State Machines</title>
  <link rel="stylesheet" href="/assets/style.css">
</head>
<body>
  <div class="landing">
    <div class="hero">
      <img src="/assets/Encryptstacean.png" alt="Encryptstacean, the orange CRABS mascott holding keys">
      <div>
        <h1>CRABS</h1>
        <p>Cryptographic Attribute-Based State Machines: attributes are state.
           CRABS unifies attribute-based encryption, CRDTs, operational
           transforms, and protocol state machines behind one C core with
           bindings for JavaScript (WebAssembly and native Node.js).</p>
      </div>
    </div>
    <div class="section-cards">
      <a class="card" href="/cookbook/" style="text-decoration:none">
        <h2>The Cookbook</h2>
        <p>Sixteen verified recipes — from "a shared count that can't be
           double-counted" to federated machines — each with runnable C,
           WebAssembly-JavaScript, and Node.js code, tested in CI.</p>
      </a>
      <div class="card">
        <h2>The Paper</h2>
        <p>Read the research. (Coming soon.)</p>
      </div>
      <div class="card">
        <h2>Protocol Specs</h2>
        <p>The v1.x protocol specification series. (Coming soon.)</p>
      </div>
    </div>
    <div class="callout">
      <img src="/assets/Unlockster.png" alt="Unlockster, the blue crab holding keys">
      <p>Tokens, policies, and merge guarantees are only as trustworthy as the
         keys and clocks behind them — each recipe states honestly what a
         pattern guarantees and what it does not.</p>
    </div>
  </div>
</body>
</html>
```

- [ ] **Step 5: Verify locally:** copy mascots for eyeballing: `mkdir -p cookbook/site/assets && cp Encryptstacean.png Unlockster.png cookbook/site/assets/`. Open `cookbook/site/index.html` in a browser and confirm tan background, orange headings, blue cards render.

- [ ] **Step 6: Commit**

```bash
git add cookbook/package.json cookbook/site/assets/style.css cookbook/site/index.html cookbook/.gitignore cookbook/site/assets/Encryptstacean.png cookbook/site/assets/Unlockster.png
git commit -m "feat(cookbook): site scaffold, palette, landing page"
```

---

### Task 2: The build script (`site/build.mjs`)

**Files:**
- Create: `cookbook/site/build.mjs`

- [ ] **Step 1: Write `cookbook/site/build.mjs`** — complete file (renders each recipe, generates the right-hand "on this page" TOC from h2/h3, injects snippet contents, renders provenance footers):

```js
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
  return html.replace(/<!--\s*PROVENANCE([\s\S]*?)-->/g, (full, inner) =>
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

// --- cookbook hub index table ---
const statusBadge = status => `<span class="badge ${status}">${status}</span>`;
const indexTable = ['<table class="recipe-index">',
  '<tr><th>#</th><th>Recipe</th><th>Status</th><th>Maturity</th><th>Languages</th><th>Section</th></tr>'];
for (const page of pages) {
  const languages = (page.meta.languages || '').split(/\s+/).filter(Boolean).join(' · ');
  indexTable.push(
    `<tr><td>${page.meta.number}</td><td><a href="/cookbook/${page.meta.slug}/">${page.meta.title}</a></td><td>${statusBadge(page.meta.status)}</td><td>${page.meta.maturity}</td><td>${languages}</td><td>${page.meta.section}</td></tr>`);
}
indexTable.push('</table>');

// --- sidebar (shared across cookbook pages) ---
const sidebarLinks = pages.map(page =>
  `<a href="/cookbook/${page.meta.slug}/">${String(page.meta.number).padStart(2, '0')} ${page.meta.title}<span class="badge ${page.meta.status}">${page.meta.status.slice(0, 4).toUpperCase()}</span></a>`).join('\n');

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
writeFileSync(join(dist, 'index.html'), readFileSync(join(cookbook, 'site', 'index.html')));

writeFileSync(join(dist, 'cookbook', 'index.html'), pageShell({
  title: 'The CRABS Cookbook',
  mainHtml: `<h1>The CRABS Cookbook</h1><p>Sixteen verified recipes. STATUS and
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
    title: `${page.meta.number} — ${page.meta.title} — CRABS Cookbook`,
    mainHtml: renderProse(page.body),
  }));
}
console.log(`Built ${pages.length} recipe pages into ${dist}`);
```

- [ ] **Step 2: Write a minimal smoke recipe** `cookbook/recipes/01-shared-count.md` with frontmatter and one prose line plus one snippet fence (content of snippet file can be a placeholder `console.log('01');` at this stage):

```markdown
---
number: 1
slug: shared-count
title: A shared count that can't be double-counted
section: Basics
status: PARTIAL
maturity: STABLE
target: crabs-wasm
languages: c wasm node
---
## Recipe

```snippet:wasm/01-shared-count.js
```
```

and `cookbook/snippets/wasm/01-shared-count.js` with `console.log('01');`.

- [ ] **Step 3: Build and verify:** `cd cookbook && node site/build.mjs`
  Expected: prints `Built 1 recipe pages into …/site/dist`; `site/dist/index.html` and `site/dist/cookbook/shared-count/index.html` exist; the recipe page contains the real snippet text `console.log('01');`, the sidebar lists recipe 01, and the hub table shows PARTIAL badge.

- [ ] **Step 4: Commit:**

```bash
git add cookbook/site/build.mjs cookbook/recipes cookbook/snippets
git commit -m "feat(cookbook): site build script with snippet injection"
```

---

### Task 3: JS snippet harness + Recipe 1 JS snippets (TDD)

**Files:**
- Create: `cookbook/tests/run-snippets.mjs`
- Create: `cookbook/snippets/node/01-shared-count.js`
- Create: `cookbook/snippets/wasm/01-shared-count.js`

- [ ] **Step 1: Write `cookbook/tests/run-snippets.mjs`:**

```js
// Executes every cookbook snippet meant for Node. Pass = exit 0 for each.
import { readdirSync } from 'fs';
import { join, dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { spawnSync } from 'child_process';

const snippetsDir = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'snippets');
const failures = [];
for (const dir of ['node', 'wasm']) {
  for (const file of readdirSync(join(snippetsDir, dir)).sort()) {
    if (!file.endsWith('.js')) continue;
    const path = join(snippetsDir, dir, file);
    const result = spawnSync(process.execPath, [path], { encoding: 'utf8' });
    if (result.status !== 0) {
      failures.push(`${dir}/${file} (exit ${result.status})\n${result.stderr}`);
    }
  }
}
if (failures.length) {
  console.error(`FAILED ${failures.length} snippet(s):\n${failures.join('\n---\n')}`);
  process.exit(1);
}
console.log('All snippets passed.');
```

- [ ] **Step 2: Run `node cookbook/tests/run-snippets.mjs`** — it currently finds only the wasm placeholder (`console.log('01');`, passes). This is fine; the harness becomes load-bearing in step 3.

- [ ] **Step 3: Write `cookbook/snippets/wasm/01-shared-count.js`** — verified against `bindings/wasm/index.d.ts` and `bindings/wasm/test/smoke.js` (executor MUST check each symbol against `cookbook/api-map.md` written in Task 5; adjust or emit a GAP REPORT if a symbol is absent):

```js
'use strict';
// Recipe 1 — a shared count that can't be double-counted (crabs-wasm, run in Node).
const { Node, KeyPair } = require('../../../bindings/wasm');

module.exports.main = main;
async function main() {
  const node = await Node.create('node-1', { ordering: 'hlc' });
  const key = await KeyPair.generate();
  node.registerUser('counter', key.publicKeyHex(), 'adult');

  node.addCounter('opens');
  node.incrementCounter('opens', 1, 'counter');
  node.incrementCounter('opens', 1, 'counter');

  const reads = node.getCounter('opens');
  console.log(reads);
  if (reads < 2) throw new Error('counter did not converge to 2');
  node.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });
```

If `require('../../../bindings/wasm')` path resolves oddly (because this is ESM-adjacent), write the snippet as CommonJS `.js` with `module.exports` untouched — `run-snippets.mjs` runs them with plain `node`, which handles CommonJS fine. Keep the file CommonJS.

- [ ] **Step 4: Verify the method names against `bindings/wasm/index.d.ts` before running.** Grep each: `addCounter`, `incrementCounter`, `getCounter`, `registerUser`, `KeyPair.generate`, `Node.create`, `destroy`. Record the actual line numbers for the provenance footer. If any is missing, check whether the intended capability exists under a different name in the d.ts; if truly absent, replace the snippet file with a GAP REPORT page (spec's gap protocol) and mark recipe status PARTIAL.

- [ ] **Step 5: Run the harness:** `node cookbook/tests/run-snippets.mjs`
  Expected: `All snippets passed.`

- [ ] **Step 6: Write `cookbook/snippets/node/01-shared-count.js`** — same recipe on the native binding: same shape, `require('../../../bindings/node')` instead. Verify against `bindings/node/index.d.ts` the way step 4 describes (the node API is slightly smaller). If `crabs-node` is not yet compiled locally, build it: `cd bindings/node && npm ci && npm run install` (cmake-js — matches its package.json `install` script), then run.

- [ ] **Step 7: Run the harness again — both snippets must pass.** Expected: `All snippets passed.`

- [ ] **Step 8: Commit:**

```bash
git add cookbook/tests/run-snippets.mjs cookbook/snippets
git commit -m "test(cookbook): snippet harness + recipe 1 wasm/node snippets"
```

---

### Task 4: C harness + Recipe 1 C snippet

**Files:**
- Create: `cookbook/prelude/c/prelude.h`
- Create: `cookbook/snippets/c/01-shared-count.c`
- Create: `cookbook/tests/run-c.sh`

**Context for the executor:** the C library builds via repo-root `CMakeLists.txt` (static lib target `crabs`, public include dir `src`, and OpenABE headers via the `deps/openabe-c` submodule: `git submodule update --init --recursive` if missing). Existing C tests use `test/test_helpers.h`, which provides `crabs_test_env_t` (`state`, `attribute_machine_t* am`, `ecdsa_keypair_t* admin_key`) via `crabs_test_env_init`/`crabs_test_env_destroy` — see `test/test_helpers.h:18-29`. The cookbook prelude reuses that scaffold rather than reimplementing it. The prelude exists so snippets stay short; it is shown once on the site (Task 5 links it), not repeated per snippet.

- [ ] **Step 1: Confirm a clean build works:** `cmake -S . -B build && cmake --build build -j` from repo root, then `ctest --test-dir build` (or reuse the existing `build/` dir if it is green). If OpenABE is missing, run `git submodule update --init --recursive` and rebuild first. If OpenABE cannot build, STOP and report — the C language surface cannot be claimed working in that case.

- [ ] **Step 2: Write `cookbook/prelude/c/prelude.h`:**

```c
#ifndef CRABS_COOKBOOK_PRELUDE_H
#define CRABS_COOKBOOK_PRELUDE_H
// Shared scaffold for cookbook C snippets: the test environment gives a real
// machine with an admin ECDSA keypair and built-in policies, so recipes stay
// about the recipe. Include AFTER crabs headers you already use.
#include "test_helpers.h"

#endif /* CRABS_COOKBOOK_PRELUDE_H */
```

`run-c.sh` adds `-I test` so `test_helpers.h` resolves — no repo changes needed.

- [ ] **Step 3: Write `cookbook/tests/run-c.sh`.** Each C snippet is standalone (contains its own `int main(void)`); the harness compiles and runs each one:

```bash
#!/usr/bin/env bash
# Compiles and runs every cookbook C snippet against the built `crabs` library.
# Pass = the snippet compiles with -Werror and exits 0 at runtime.
set -euo pipefail
cd "$(dirname "$0")/../.."

BUILD_DIR=build
SNIPPETS=cookbook/snippets/c
OUT=cookbook/snippets/.c-out
mkdir -p "$OUT"

cmake -S . -B "$BUILD_DIR" >/dev/null
cmake --build "$BUILD_DIR" -j >/dev/null

for snippet in "$SNIPPETS"/*.c; do
  name=$(basename "$snippet" .c)
  cc -std=c11 -Wall -Werror \
    -I src -I deps/openabe-c/include -I test -I cookbook/prelude/c \
    "$snippet" -o "$OUT/$name" \
    -L"$BUILD_DIR" -lcrabs -lm -lpthread
  if ! "$OUT/$name"; then
    echo "FAILED: $snippet (runtime)"; exit 1
  fi
  echo "OK: $snippet"
done
echo 'All C snippets passed.'
```

If `-lcrabs` link resolution needs the exact archive path, use `"$BUILD_DIR/libcrabs.a"` as a direct positional reference (before the trailing libs) instead of `-L/-l`. Adjusting that one line to make linking real is expected; do not fake a link.

- [ ] **Step 4: Write `cookbook/snippets/c/01-shared-count.c`.** Before writing, read the existing C CRDT counter usage: `test/test_crdt.cpp` (and `src/CRDT/crdt_merge.c`) to mirror real names (likely `attribute_machine` ops such as `attribute_machine_add_*` / counter increment verbs — record exact file:line from `src/` headers into the provenance footer). The snippet's shape:

```c
/* Recipe 1 — a shared count that can't be double-counted (C, native).
   Prelude (shown once on the cookbook site) supplies the test environment:
   test_helpers.h → crabs_test_env_init(). */
#include "prelude.h"
#include "CRDT/crdt_*.h"   /* executor: exact CRDT counter header from src/ */

int main(void) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);

  /* executor: create the counter, increment it twice, read it back,
     and assert the read count == 2 — mirroring names from test_crdt.cpp. */

  crabs_test_env_destroy(&env);
  return 0;
}
```

The `CRDT/crdt_*.h` line above is **intentionally not the real include** — writing the snippet is the step's work: find the real counter API in `src/CRDT/`, mirror test usage, embed an assert (plain `if (...) return 1;` or the test_helpers assert style used by existing C tests). C snippets must compile with `-Wall -Werror`.

- [ ] **Step 5: Verify:** `bash cookbook/tests/run-c.sh` — expected final line `All C snippets passed.`

- [ ] **Step 6: Commit:**

```bash
chmod +x cookbook/tests/run-c.sh
git add cookbook/prelude/c cookbook/snippets/c cookbook/tests/run-c.sh
git commit -m "test(cookbook): C snippet harness + recipe 1 native snippet"
```

---

### Task 5: The API map (recon deliverable)

**Files:**
- Create: `cookbook/api-map.md`

This file is the source of truth every recipe's provenance footer cites. It is generated by hand reading, not invented.

- [ ] **Step 1: Read `bindings/wasm/index.d.ts` and `bindings/node/index.d.ts` in full.**
- [ ] **Step 2: Skim every file in `bindings/wasm/test/` and `bindings/node/test/`, and `examples/video_platform_p2p/`.**
- [ ] **Step 3: Write `cookbook/api-map.md`** — a table per exported class: `symbol → kind → signature summary → source file:line → maturity (STABLE = exercised in tests | PRESENT = in d.ts only)`. Include one section per CRDT type, the policy/dedup surface, schedules, triggers, ABE encrypt, lineage spawn/attest/tombstone, write domains, wire versions, HandlerState.
- [ ] **Step 4: Cross-check** that every symbol this plan's per-recipe capability lists (Tasks 7–21) name appears in the map, adding whatever is missing.
- [ ] **Step 5: Commit:**

```bash
git add cookbook/api-map.md
git commit -m "docs(cookbook): API map with file:line and maturity labels"
```

---

### Task 6: Recipe 1's page (works the full authoring pipeline end to end)

**Files:**
- Modify: `cookbook/recipes/01-shared-count.md` (replace Task 2's stub)
- Create: `cookbook/snippets/c/01-shared-count-provenance-note.md` — no; provenance lives inline in the recipe md as HTML comments adjacent to each snippet fence.

- [ ] **Step 1: Author the full recipe md** — sections: Intent, The naive version and where it breaks, The shape, What it guarantees / what it doesn't, Variations; then per language a `snippet:` fence + provenance footer comment citing api-map-backed `file:line` for every symbol (`Node.create`, `KeyPair.generate`, `registerUser`, `addCounter`, `incrementCounter`, `getCounter`, `destroy` for wasm; the native equivalents for node; the C counters used). `verified:` says `executed` only because Tasks 3–4 actually ran these.

The provenance footer shape in the md (rendered into the visible footer box by `build.mjs`):

```markdown
<!-- PROVENANCE
target: crabs-wasm
verified: executed
symbols:
  Node.create           cookbook/api-map.md#node-create  (bindings/wasm/index.d.ts:NNN)
  ...
maturity: STABLE
test_ref: bindings/wasm/test/smoke.js:1
-->
```

- [ ] **Step 2: Build + eyeball:** `node cookbook/site/build.mjs` then open `site/dist/cookbook/shared-count/index.html` in a browser — snippet code appears in a baby-blue block with a visible provenance footer; sidebar active state is orange.
- [ ] **Step 3: Set `status: COMPLETE` in frontmatter** (all three languages delivered real code).
- [ ] **Step 4: Commit.**

```bash
git add cookbook/recipes/01-shared-count.md
git commit -m "docs(cookbook): recipe 1 — shared count, three languages, provenance"
```

---

### Task 7 (`recipes 2–5 — Basics`)

Repeat the full Recipe-1 procedure (author prose → snippets in one language at a time, verify each against `api-map.md` → run harnesses → provenance → build → commit) for four recipes. Per-recipe capability requirements and closest known-good references:

| # | slug/title | Capabilities needed | Closest references |
|---|---|---|---|
| 2 | one-vote-per-member | one-shot set + guard-before-mutate dedup; **check `DedupSpec.PER_USER` against api-map first** — it may not exist in bindings; if absent the guard-by-ONESHOT-SET half is still real and the tally half may be PARTIAL | `bindings/wasm/test/handler-reads.js`, C `test/test_dedup.cpp` |
| 3 | execute-once | ONE_SHOT_FLAG + global dedup | C `test/test_dedup.cpp` |
| 4 | roles-and-policies | registerUser/grantRole/setPolicy + authz rejection | `bindings/wasm/test/smoke.js` |
| 5 | member-profile | register LWW + key versioning (KeyPair) | `bindings/wasm/test/registers.js` |

- [ ] Steps per recipe (one commit each): snippets for c/node/wasm → run harnesses → author md → build → eyeball → commit.
- [ ] **Gap rule:** if a capability (e.g. `DedupSpec.PER_USER`) is absent from a binding, that language's snippet is replaced by a GAP REPORT in the page and the recipe's frontmatter status becomes `PARTIAL`. Never invent.

---

### Task 8: Recipes 6–7 (Conditions)

| # | slug/title | Capabilities needed | Closest references |
|---|---|---|---|
| 6 | progressive-disclosure-moderation | trigger + threshold attributes + ABE `encrypt` | `example` ABE surface: `bindings/wasm/index.d.ts` encrypt + C `test/test_attribute_machine.cpp` |
| 7 | timed-actions | schedules + `setTimeSource` | `bindings/wasm/test/schedules.js`, `test/time-source.js` |

Same per-recipe steps and gap rule as Task 7.

---

### Task 9: Recipes 8 + 8b (Convergence)

| # | slug/title | Capabilities needed | Closest references |
|---|---|---|---|
| 8 | reorderable-list | OT ordered set surface — **verify `OT_ORDERED_SET` exposure in `bindings/*/index.d.ts`**; it exists natively (`src/OT/ot_ordered_set.h`) but may not be bound in JS | `src/OT/ot_ordered_set.h`, C `test/` files covering OT |
| 8b | rich-text (gap page) | OT_DOCUMENT — *implemented, not benchmarked* | `src/OT/ot_document.h`, `docs/CRABS_Extended.pdf` §13.1 |

- [ ] Recipe 8: if the JS bindings do not expose the OT ordered set, the JS side is a GAP REPORT page saying "surface exists in C, not yet bound in wasm/node" and the page status is PARTIAL with the C snippet delivered — this is exactly the honest split the excerpt wants.
- [ ] Recipe 8b: a *separate page*, `status: UNSUPPORTED`, `maturity: EXPERIMENTAL`, stating plainly: implemented but unmeasured; do not build rich text on it until a benchmark exists. No code block may present it as runnable.

---

### Task 10: Recipes 9–10 (Coordination)

| # | slug/title | Capabilities needed | Closest references |
|---|---|---|---|
| 9 | treasury-atomic-transfers | RESOURCE + lock protocol + tx manager — **verify against api-map; likely PARTIAL** | C `test/` covering resources; `docs/superpowers/plans/` |
| 10 | private-but-accountable | Mode B signing | `bindings/wasm/test/write-domains.js` (sovereign/chain ops), `Operation.sign` |

Same per-recipe steps and gap rule.

---

### Task 11: Recipes 11–14 (Composition)

| # | slug/title | Capabilities needed | Closest references |
|---|---|---|---|
| 11 | subgroups-without-escalation | Blueprint + lineage spawn + attenuation | `bindings/wasm/index.d.ts` Blueprint; `bindings/*/lineage_smoke.mjs` |
| 12 | federation-between-machines | attestations + parent key chain | `bindings/*/lineage_smoke.mjs` |
| 13 | sovereign-ledger | write domain SOVEREIGN | `bindings/wasm/test/write-domains.js` |
| 14 | strict-ordering-market | GROUP-ORDERED domain + elected ordering module — **likely PARTIAL (module may exist only in C or only in design)** | `src/` consensus/`Raft`-adjacent code; `docs/superpowers/plans/` |

Same per-recipe steps and gap rule.

---

### Task 12: Recipes 15–16 (Ground truth)

| # | slug/title | Capabilities needed | Closest references |
|---|---|---|---|
| 15 | hardware-attested-policy | hardware attestation namespace as an attribute | api-map (find the attestation surface); C tests near lineage/attestation |
| 16 | revocable-data | key versioning + epoch attributes | `bindings/wasm/test/registers.js`, C `test/test_key_lifecycle.cpp` |

Same per-recipe steps and gap rule.

---

### Task 13: Interactive in-browser demos

**Files:**
- Create: `cookbook/site/interactive/panel.js`
- Create: `cookbook/site/interactive/01-shared-count.html`
- Modify: `cookbook/recipes/01-shared-count.md` (embed panel iframe + reference)
- Modify: `cookbook/site/build.mjs` (emit the interactive assets into dist)

**Pattern to follow:** `examples/devtools_demo/index.html` loads the dev wasm bundle and drives live ops in the browser. Read it first. The recipe interactive panels use the same loading approach with the locked palette, at a much smaller scope — no devtools panel, just buttons + a live state readout.

- [ ] **Step 1: Write `cookbook/site/interactive/panel.js`** — a small vanilla-JS page module: buttons "spawn node", "increment ×1", "merge from second node"; the state line reflects `getCounter` after each click; errors surface in the panel. Load the bundle from `/vendor/crabs.dev.js` per the loader pattern from `examples/devtools_demo/index.html` (including whatever locateFile/module config it uses to point at `crabs.dev.wasm`).
- [ ] **Step 2: Modify `build.mjs`:** copy `bindings/wasm/crabs.dev.js`, `crabs.dev.wasm` into `site/dist/assets/wasm/` and emit `site/interactive/*` into `dist/cookbook/<slug>/interactive.html` for recipes whose frontmatter gains `interactive: true`. Add `interactive: true` to recipe 1's frontmatter and embed the panel in its page via `<iframe src="/cookbook/shared-count/interactive.html">` framed with `<div class="interactive">`.
- [ ] **Step 3: Build and click it yourself:** `node cookbook/site/build.mjs`, serve `site/dist` (`python3 -m http.server 8080 -d site/dist`), open `/cookbook/shared-count/`, click the buttons, confirm the counter readout changes and no console errors.
- [ ] **Step 4: Commit.**

---

### Task 14: Playwright browser harness

**Files:**
- Create: `cookbook/tests/browser.js`

- [ ] **Step 1: Write `cookbook/tests/browser.js`:**

```js
// Serves site/dist, loads each interactive page, drives it, asserts visible change.
import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync } from 'fs';
import { join, dirname, extname, resolve } from 'path';
import { fileURLToPath } from 'url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'site', 'dist');
const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript',
               '.wasm': 'application/wasm', '.png': 'image/png' };
const server = createServer((req, res) => {
  try {
    const url = req.url.split('?')[0].replace(/^\/|\/$/g, '') || 'index.html';
    const body = readFileSync(join(root, url));
    res.writeHead(200, { 'Content-Type': MIME[extname(url)] || 'application/octet-stream' });
    res.end(body);
  } catch (e) { res.writeHead(404); res.end('not found'); }
}).listen(8106);

const browser = await chromium.launch();
const page = await browser.newPage();
const consoleErrors = [];
page.on('pageerror', e => consoleErrors.push(e.message));
await page.goto('http://127.0.0.1:8106/cookbook/shared-count/');
await page.screenshot({ path: 'cookbook/tests/.screens/shared-count.png', fullPage: true });

// Interactive panel: the counter readout must change after clicking increment.
const frame = page.frame({ url: /interactive\.html$/ }) ||
              (page.frames().find(f => f.url().includes('interactive.html')));
if (!frame) throw new Error('interactive panel iframe not found');
const before = await frame.textContent('[data-state="counter"]');
await frame.click('[data-action="increment"]');
await page.waitForTimeout(300);
const after = await frame.textContent('[data-state="counter"]');
if (before === after) throw new Error(`interactive panel did not change state (${before} → ${after})`);

if (consoleErrors.length) throw new Error('console errors: ' + consoleErrors.join('; '));
await browser.close();
server.close();
console.log('Browser checks passed.');
process.exit(0);
```

- [ ] **Step 2: Run `npx playwright install chromium` once (local + CI), then `npm run test:browser`.** Expected: `Browser checks passed.` If the panel selector names differ from what Task 13 actually wrote, fix the spec's selectors to match reality — the assertion (state changes, no console errors) is normative.
- [ ] **Step 3: Commit.**

---

### Task 15: GitHub Actions workflow (test + deploy)

**Files:**
- Create: `.github/workflows/cookbook-site.yml`

- [ ] **Step 1: Write the workflow:**

```yaml
name: cookbook-site
on:
  push:
    branches: [master]
    paths: ['cookbook/**', 'bindings/**', '.github/workflows/cookbook-site.yml']
  pull_request:
    paths: ['cookbook/**', 'bindings/**']
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: pages
  cancel-in-progress: false

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # deps/openabe-c is required to build the C library and run C snippets.
      - name: Init submodules
        run: git submodule update --init --recursive
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - name: Build native binding
        run: cd bindings/node && npm ci && npm run install
      - name: Install cookbook deps
        run: cd cookbook && npm ci
      - name: JS snippets
        run: cd cookbook && npm run test:snippets
      - name: C snippets
        run: cd cookbook && npm run test:c
      - name: Install playwright browser
        run: cd cookbook && npx playwright install --with-deps chromium
      - name: Browser snippets
        run: cd cookbook && npm run test:browser
  deploy:
    needs: test
    if: github.ref == 'refs/heads/master'
    runs-on: ubuntu-latest
    environment: github-pages
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - name: Init submodules
        run: git submodule update --init --recursive
      - name: Build site
        run: cd cookbook && npm ci && node site/build.mjs
      - uses: actions/configure-pages@v5
      - uses: actions/upload-pages-artifact@v3
        with: { path: cookbook/site/dist }
      - uses: actions/deploy-pages@v4
```

Caveat to verify on first CI run: C snippet harness needs OpenABE built by the root cmake — expected to work since the repo's own tests build this way; if CI takes >20 min building OpenABE, split C snippets into a separate job so Pages deploys stay fast, but do not skip C.

- [ ] **Step 2: Enable GitHub Pages:** repo Settings → Pages → Build and deployment → Source: **GitHub Actions**. (User does this in the UI; note it in the final report.)
- [ ] **Step 3: Commit.**

---

### Task 16: End-to-end verification + polish

- [ ] **Step 1: Run everything:** `cd cookbook && npm run test:snippets && npm run test:c && npm run test:browser` — all green.
- [ ] **Step 2: Build + serve:** `node site/build.mjs && python3 -m http.server 8080 -d site/dist` — walk the landing page, hub, and all recipe pages; check sidebar active states, statuses, provenance boxes, interactive panels, light theme, mascots.
- [ ] **Step 3: README note:** add a short "Cookbook: https://vijayee.github.io/CRABS/" line pointing at the site from the repo README (verify the actual Pages URL once deploy lands — it will be `https://vijayee.github.io/CRABS/` only if Pages serves the user-repo root; adjust to the real URL after first deploy).
- [ ] **Step 4: Final commit, push, open the Pages URL, confirm live.** (Pushing requires the user's go-ahead per repo norms — ask before pushing.)