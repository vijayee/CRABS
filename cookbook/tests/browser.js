//
// browser.js — Playwright harness for the cookbook's interactive demos.
//
// Serves cookbook/site/dist over an ephemeral local static server, loads the
// real recipe page (so the embedded iframe contract stays honest), drives the
// A-shared-count demo inside its iframe, and asserts: the counter readout
// becomes numeric after the first increment, grows by exactly 1 per click,
// the demo never surfaces its error state, and the console/page error logs
// stay clean. On failure it screenshots to tests/.screens/failure.png before
// rethrowing.
//
import { chromium } from 'playwright';
import { createServer } from 'http';
import { readFileSync } from 'fs';
import { mkdirSync, } from 'fs';
import { join, dirname, extname, resolve, sep } from 'path';
import { fileURLToPath } from 'url';

const recipeUrl = '/cookbook/shared-count/';
const iframeSelector = 'iframe[title="Interactive demo — A shared count"]';
const screenDir = resolve(dirname(fileURLToPath(import.meta.url)), '.screens');
const distRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'site', 'dist');
const port = 8237;

const MIME = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'text/javascript',
  '.mjs': 'text/javascript',
  '.wasm': 'application/wasm',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
};

const awaitReady = new Promise((listening, failed) => {
  const server = createServer((req, res) => {
    const urlPath = req.url.split('?')[0].replace(/^\/|\/$/g, '') || 'index.html';
    let filePath = resolve(distRoot, urlPath);
    if (!filePath.startsWith(distRoot + sep)) {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    try {
      const body = readFileSync(filePath);
      res.writeHead(200, { 'Content-Type': MIME[extname(urlPath)] || 'application/octet-stream' });
      res.end(body);
    } catch (notAFile) {
      // Directory-style URLs (…/shared-count/) resolve to their index.html.
      try {
        filePath = join(filePath, 'index.html');
        const body = readFileSync(filePath);
        res.writeHead(200, { 'Content-Type': MIME[extname(filePath)] || 'application/octet-stream' });
        res.end(body);
      } catch (missing) {
        res.writeHead(404);
        res.end('not found');
      }
    }
  });
  server.once('error', (listenError) => {
    failed(new Error(`static server could not bind fixed port ${port} ` +
      `(CI needs a deterministic port; free it or stop the other process): ${listenError.message}`));
  });
  server.listen(port, '127.0.0.1', () => listening(server));
});
const server = await awaitReady;

const browser = await chromium.launch();
const page = await browser.newPage();
try {
  const pageErrors = [];
  const consoleErrors = [];
  page.on('pageerror', (pageError) => pageErrors.push(pageError.message));
  page.on('console', (consoleMessage) => {
    if (consoleMessage.type() === 'error') consoleErrors.push(consoleMessage.text());
  });

  await page.goto(`http://127.0.0.1:${port}${recipeUrl}`);

  // The demo boots lazily: the first click triggers the ~1.8 MB wasm load, so
  // never sleep — wait on the readout turning numeric (generous timeout for
  // slow CI links).
  const longTimeout = 60000;
  const iframeElement = page.locator(iframeSelector);
  const iframeHandle = await iframeElement.elementHandle({ timeout: 15000 });
  const frame = iframeHandle && await iframeHandle.contentFrame();
  if (!frame) throw new Error(`demo iframe "${iframeSelector}" never produced a document frame`);
  const readout = frame.locator('[data-state="counter"]');
  const incrementButton = frame.locator('[data-action="increment"]');

  await incrementButton.click({ timeout: longTimeout });
  await frame.waitForFunction(() =>
    !Number.isNaN(Number(document.querySelector('[data-state="counter"]').textContent)),
  undefined, { timeout: longTimeout });
  const before = Number(await readout.textContent());

  await incrementButton.click({ timeout: longTimeout });
  await frame.waitForFunction((previousValue) =>
    Number(document.querySelector('[data-state="counter"]').textContent) > previousValue,
  before, { timeout: longTimeout });
  const after = Number(await readout.textContent());
  if (after !== before + 1) {
    throw new Error(`counter grew by ${after - before}, expected exactly 1 (${before} -> ${after})`);
  }

  const statusElement = frame.locator('[data-status]');
  const statusClass = await statusElement.getAttribute('class');
  if (statusClass && statusClass.includes('error')) {
    throw new Error(`demo surfaced an error state: ${await statusElement.textContent()}`);
  }

  if (consoleErrors.length) {
    throw new Error('console errors: ' + consoleErrors.join(' | '));
  }
  if (pageErrors.length) {
    throw new Error('page errors: ' + pageErrors.join(' | '));
  }

  console.log(`Browser checks passed (counter ${before} -> ${after}).`);
} catch (failure) {
  mkdirSync(screenDir, { recursive: true });
  if (page) {
    await page.screenshot({ path: join(screenDir, 'failure.png'), fullPage: true })
      .catch((screenshotError) => console.error(`screenshot also failed: ${screenshotError.message}`));
  }
  throw failure;
} finally {
  await browser.close();
  server.close();
}
process.exit(0);