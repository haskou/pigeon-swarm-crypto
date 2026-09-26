const assert = require('node:assert/strict');
const {
  createPrivateKey,
  createPublicKey,
  sign,
} = require('node:crypto');
const { createServer } = require('node:http');
const canonicalize = require('canonicalize');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const { PrivateFreshnessProof } = require('../../dist');

(async () => {
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.alloc(32, 17),
  ]);
  const key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const signerKey = createPublicKey(key)
    .export({ format: 'der', type: 'spki' })
    .subarray(-32)
    .toString('base64url');
  const encoded = (byte) => Buffer.alloc(32, byte).toString('base64url');
  const request = {
    version: 1,
    scopeId: encoded(1),
    nonce: encoded(2),
    expectedRevision: 7,
    expectedHeadHash: encoded(3),
    batchCommitment: encoded(4),
  };
  const unsigned = {
    version: 1,
    scopeId: request.scopeId,
    nonce: request.nonce,
    revision: request.expectedRevision,
    headHash: request.expectedHeadHash,
    batchCommitment: request.batchCommitment,
    signerKey,
  };
  const bytes = Buffer.from(
    'pigeon.private-freshness.v1\0' + canonicalize(unsigned),
  );
  const signed = canonicalize({
    ...unsigned,
    signature: sign(null, bytes, key).toString('base64url'),
  });
  const requestJson = JSON.stringify(request);
  assert.equal(
    PrivateFreshnessProof.verify(signed, signerKey, requestJson),
    signed,
  );

  const bundle = await build({
    stdin: {
      contents: "export { PrivateFreshnessProof } from './dist/index.js';",
      resolveDir: process.cwd(),
    },
    bundle: true,
    format: 'iife',
    globalName: 'PigeonCrypto',
    platform: 'browser',
    write: false,
  });
  const server = createServer((_request, response) => {
    response.setHeader('Content-Type', 'text/html');
    response.end(
      '<!doctype html><title>Disposable freshness interoperability test</title>',
    );
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:' + server.address().port);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const result = await page.evaluate(
      async ({ signed, signerKey, requestJson, der, bytes, unsigned }) => {
        const verified = PigeonCrypto.PrivateFreshnessProof.verify(
          signed,
          signerKey,
          requestJson,
        );
        const privateKey = await crypto.subtle.importKey(
          'pkcs8',
          Uint8Array.from(der),
          { name: 'Ed25519' },
          false,
          ['sign'],
        );
        const signature = new Uint8Array(
          await crypto.subtle.sign('Ed25519', privateKey, Uint8Array.from(bytes)),
        );
        const encodedSignature = btoa(String.fromCharCode(...signature))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        const nativeSigned = JSON.stringify({
          ...unsigned,
          signature: encodedSignature,
        });
        const nativeVerified = PigeonCrypto.PrivateFreshnessProof.verify(
          nativeSigned,
          signerKey,
          requestJson,
        );
        let mismatchRejected = false;
        try {
          PigeonCrypto.PrivateFreshnessProof.verify(
            nativeSigned,
            signerKey,
            JSON.stringify({
              ...JSON.parse(requestJson),
              nonce: 'CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk',
            }),
          );
        } catch (error) {
          mismatchRejected =
            error.message === 'Invalid private freshness proof';
        }
        return { verified, nativeVerified, mismatchRejected };
      },
      {
        signed,
        signerKey,
        requestJson,
        der: [...der],
        bytes: [...bytes],
        unsigned,
      },
    );
    assert.deepEqual(result, {
      verified: signed,
      nativeVerified: signed,
      mismatchRejected: true,
    });
    console.log(
      'PASS Node, Chromium and native WebCrypto agree on private freshness proofs; mismatched challenges are rejected.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
