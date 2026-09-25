const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const {
  ProtectedUserRootKey,
  UserRootKey,
  UserRootKeySecondFactor,
} = require('../../dist');

(async () => {
  const password = 'Correct-horse-battery-staple-7!';
  const rootKey = UserRootKey.generate();
  const factor = UserRootKeySecondFactor.generate();
  const protectedByNode = await ProtectedUserRootKey.create(
    rootKey,
    password,
    factor,
  );
  const bundle = await build({
    stdin: {
      contents:
        "export { ProtectedUserRootKey, UserRootKey, UserRootKeySecondFactor } from './dist/index.js';",
      resolveDir: process.cwd(),
    },
    bundle: true,
    format: 'iife',
    globalName: 'PigeonCrypto',
    platform: 'browser',
    write: false,
  });
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', 'text/html');
    response.end('<!doctype html><title>User root key runtime test</title>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:' + server.address().port);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const result = await page.evaluate(
      async ({ password, root, factor, protectedByNode }) => {
        const {
          ProtectedUserRootKey,
          UserRootKey,
          UserRootKeySecondFactor,
        } = PigeonCrypto;
        const browserRoot = UserRootKey.fromBase64(root);
        const browserFactor = UserRootKeySecondFactor.fromBase64(factor);
        const unlocked = await new ProtectedUserRootKey(
          protectedByNode,
        ).unlock(password, browserFactor);
        const protectedByBrowser = await ProtectedUserRootKey.create(
          browserRoot,
          password,
          browserFactor,
        );
        let wrongFactorRejected = false;
        try {
          await protectedByBrowser.unlock(
            password,
            UserRootKeySecondFactor.generate(),
          );
        } catch (error) {
          wrongFactorRejected =
            error.message === 'Invalid protected user root key';
        }
        return {
          protectedByBrowser: protectedByBrowser.valueOf(),
          unlocked: unlocked.valueOf(),
          wrongFactorRejected,
        };
      },
      {
        password,
        root: rootKey.valueOf(),
        factor: factor.valueOf(),
        protectedByNode: protectedByNode.valueOf(),
      },
    );
    assert.equal(result.unlocked, rootKey.valueOf());
    assert.equal(result.wrongFactorRejected, true);
    assert.equal(
      (
        await new ProtectedUserRootKey(result.protectedByBrowser).unlock(
          password,
          factor,
        )
      ).valueOf(),
      rootKey.valueOf(),
    );
    console.log(
      'PASS Node and bundled Chromium exchange password-plus-factor protected user root keys.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
