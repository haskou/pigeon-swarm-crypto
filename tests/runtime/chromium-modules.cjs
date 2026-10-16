const { readFile } = require('node:fs/promises');
const { createServer } = require('node:http');
const path = require('node:path');
const { build } = require('esbuild');
const { chromium } = require('playwright');

/** A browser ESM bundle of `contents`, resolved from the package root. */
const bundled = async (contents) =>
  (
    await build({
      stdin: { contents, resolveDir: process.cwd() },
      bundle: true,
      format: 'esm',
      platform: 'browser',
      write: false,
    })
  ).outputFiles[0].text;

/**
 * Serves the browser MLS bundle as /mls.mjs, the root KeyPair as /root.mjs,
 * the ts-mls API the tampering scenarios build hostile messages with as
 * /ts-mls.mjs and `module` (a file next to this one) as /cases.mjs, then
 * returns what `run(imports, argument)` of /cases.mjs resolves to in
 * Chromium.
 */
const runInChromium = async (module, argument) => {
  const files = {
    '/cases.mjs': await readFile(path.join(__dirname, module)),
    '/mls.mjs': await readFile('dist/mls/index.mjs'),
    '/root.mjs': await bundled("export { KeyPair } from './dist/index.js';"),
    '/ts-mls.mjs': await bundled(
      [
        'export {',
        '  createCommit, createProposal, decodeGroupState, decodeMlsMessage,',
        '  defaultAuthenticationService, defaultCapabilities,',
        '  defaultKeyPackageEqualityConfig, defaultKeyRetentionConfig,',
        '  defaultLifetime, defaultLifetimeConfig, defaultPaddingConfig,',
        '  encodeGroupState, encodeMlsMessage, generateKeyPackage,',
        '  getCiphersuiteFromName, getCiphersuiteImpl,',
        "} from 'ts-mls';",
      ].join('\n'),
    ),
  };
  const server = createServer((request, response) => {
    const file = files[request.url];

    response.setHeader('Content-Type', file ? 'text/javascript' : 'text/html');
    response.end(file ?? '<!doctype html><title>MLS runtime test</title>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:' + server.address().port);

    return await page.evaluate(async (value) => {
      const mls = await import('/mls.mjs');
      const { KeyPair } = await import('/root.mjs');
      const tsMls = await import('/ts-mls.mjs');
      const { run } = await import('/cases.mjs');

      return run({ KeyPair, mls, tsMls }, value);
    }, argument);
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
};

module.exports = { runInChromium };
