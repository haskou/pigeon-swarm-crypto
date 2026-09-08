const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { createPrivateKey, createPublicKey, verify } = require('node:crypto');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const { PrivateKey, PrivateOperationSignature } = require('../../dist');

(async () => {
  const keyDer = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.alloc(32, 7),
  ]);
  const nativeKey = createPrivateKey({
    key: keyDer,
    format: 'der',
    type: 'pkcs8',
  });
  const publicKey = createPublicKey(nativeKey);
  const pem = nativeKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const author = publicKey
    .export({ format: 'der', type: 'spki' })
    .subarray(-32)
    .toString('base64url');
  const input = JSON.stringify({
    version: 1,
    operationId: Buffer.alloc(16, 1).toString('base64url'),
    scopeId: Buffer.alloc(32, 2).toString('base64url'),
    authorizationRevision: 0,
    authorDeviceKey: author,
    kind: 'message.create',
    previousOperationIds: [],
    payload: { text: 'Unicode: é 😀', number: 1e30 },
  });
  const nodeSigned = PrivateOperationSignature.sign(
    input,
    PrivateKey.fromPEM(pem),
  );
  const bundle = await build({
    stdin: {
      contents:
        "export { PrivateKey, PrivateOperationSignature } from './dist/index.js';",
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
    response.end(
      '<!doctype html><title>Disposable signature interoperability test</title>',
    );
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    page.on('pageerror', (error) => console.error(error.message));
    await page.goto('http://127.0.0.1:' + server.address().port);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const result = await page.evaluate(
      async ({ input, pem, author, nodeSigned, der }) => {
        const { PrivateKey, PrivateOperationSignature } = PigeonCrypto;
        const signed = PrivateOperationSignature.sign(
          input,
          PrivateKey.fromPEM(pem),
        );
        const verified = PrivateOperationSignature.verify(nodeSigned, author);
        const parsed = JSON.parse(signed);
        const signature = parsed.signature;
        delete parsed.signature;
        const bytes = new TextEncoder().encode(
          'pigeon.private-operation.v1\0' + JSON.stringify(parsed),
        );
        const fromBase64Url = (value) =>
          Uint8Array.from(
            atob(value.replace(/-/g, '+').replace(/_/g, '/')),
            (char) => char.charCodeAt(0),
          );
        const nativePublic = await crypto.subtle.importKey(
          'raw',
          fromBase64Url(author),
          { name: 'Ed25519' },
          false,
          ['verify'],
        );
        const nativeVerified = await crypto.subtle.verify(
          'Ed25519',
          nativePublic,
          fromBase64Url(signature),
          bytes,
        );
        const nativePrivate = await crypto.subtle.importKey(
          'pkcs8',
          Uint8Array.from(der),
          { name: 'Ed25519' },
          false,
          ['sign'],
        );
        const nativeSignature = new Uint8Array(
          await crypto.subtle.sign('Ed25519', nativePrivate, bytes),
        );
        const encoded = btoa(String.fromCharCode(...nativeSignature))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        const nativeSigned = JSON.stringify({ ...parsed, signature: encoded });
        const nativeAccepted = PrivateOperationSignature.verify(
          nativeSigned,
          author,
        );
        let duplicateRejected = false;
        try {
          PrivateOperationSignature.verify(
            nodeSigned.replace('"version":1', '"version":2,"version":1'),
            author,
          );
        } catch (error) {
          duplicateRejected = error.message === 'Invalid private operation';
        }
        return {
          signed,
          verified,
          nativeVerified,
          nativeAccepted,
          duplicateRejected,
        };
      },
      { input, pem, author, nodeSigned, der: [...keyDer] },
    );
    assert.equal(result.signed, nodeSigned);
    assert.equal(result.verified, nodeSigned);
    assert.equal(result.nativeAccepted, nodeSigned);
    assert.equal(result.nativeVerified, true);
    assert.equal(result.duplicateRejected, true);
    const parsed = JSON.parse(result.signed);
    const signature = Buffer.from(parsed.signature, 'base64url');
    delete parsed.signature;
    assert.equal(
      verify(
        null,
        Buffer.from('pigeon.private-operation.v1\0' + JSON.stringify(parsed)),
        publicKey,
        signature,
      ),
      true,
    );
    console.log(
      'PASS Node, bundled browser and native WebCrypto agree on operation signatures; duplicate properties are rejected.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
