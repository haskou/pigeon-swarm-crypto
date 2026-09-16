const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { build } = require('esbuild');
const { chromium } = require('playwright');

async function withinDeadline(operation, label) {
  let timer;
  try {
    return await Promise.race([
      operation,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${label} exceeded 30 seconds`)),
          30_000,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

(async () => {
  const scenario = await import('./lifecycle.mjs');
  const nodeResult = await withinDeadline(
    scenario.runLifecycle(),
    'Node lifecycle',
  );
  const bundle = await build({
    entryPoints: [__dirname + '/lifecycle.mjs'],
    bundle: true,
    format: 'iife',
    globalName: 'MlsEvaluation',
    platform: 'browser',
    write: false,
  });
  const server = createServer((req, res) =>
    res.end('<!doctype html><title>MLS evaluation</title>'),
  );
  let browser;
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:' + server.address().port);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const browserResult = await withinDeadline(
      page.evaluate(() => MlsEvaluation.runLifecycle()),
      'Chromium lifecycle',
    );
    assert.deepEqual(browserResult, nodeResult);
    console.log(
      'PASS Node and Chromium MLS lifecycle:',
      JSON.stringify(nodeResult),
    );
  } finally {
    try {
      if (browser) await withinDeadline(browser.close(), 'Chromium cleanup');
    } finally {
      server.closeAllConnections();
      await new Promise((resolve) => server.close(resolve));
    }
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
