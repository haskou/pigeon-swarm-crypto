const assert = require('node:assert/strict');
const {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} = require('node:crypto');
const { createServer } = require('node:http');
const canonicalize = require('canonicalize');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const { PrivateGenesisSignature } = require('../../dist');

(async () => {
  const der = Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.alloc(32, 7),
  ]);
  const key = createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
  const owner = createPublicKey(key)
    .export({ format: 'der', type: 'spki' })
    .subarray(-32)
    .toString('base64url');
  const encoded = (byte) => Buffer.alloc(32, byte).toString('base64url');
  const hash = (value) =>
    createHash('sha256').update(canonicalize(value)).digest('base64url');
  const policy = {
    version: 1,
    devices: [{ deviceKey: owner, mlsCredentialHash: encoded(4) }],
    authorityKeys: [owner],
    threshold: 1,
    sequencerKey: owner,
    freshnessAuthorityKey: owner,
    leaseRevocationKey: owner,
    leaseRevocationHpkeKey: encoded(5),
  };
  const head = {
    scopeId: encoded(1),
    revision: 0,
    parentHeadHash: null,
    mlsEpoch: 0,
    mlsContextHash: encoded(2),
    policyHash: hash(policy),
  };
  const unsigned = { version: 1, ...head, headHash: hash(head), policy };
  const bytes = Buffer.from(
    'pigeon.private-genesis.v1\0' + canonicalize(unsigned),
  );
  const signature = sign(null, bytes, key).toString('base64url');
  const signed = canonicalize({
    ...unsigned,
    signatures: { [owner]: signature },
  });
  assert.equal(
    PrivateGenesisSignature.verify(
      signed,
      owner,
      head.scopeId,
      head.mlsContextHash,
    ),
    signed,
  );
  const bundle = await build({
    stdin: {
      contents:
        "export { PrivateKey, PrivateGenesisSignature } from './dist/index.js';",
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
      '<!doctype html><title>Disposable genesis interoperability test</title>',
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
      async ({ signed, unsigned, pem, owner, scope, context, bytes, der }) => {
        const { PrivateKey, PrivateGenesisSignature } = PigeonCrypto;
        const accepted = PrivateGenesisSignature.verify(
          signed,
          owner,
          scope,
          context,
        );
        const generated = PrivateGenesisSignature.sign(
          unsigned,
          PrivateKey.fromPEM(pem),
        );
        const nativeKey = await crypto.subtle.importKey(
          'pkcs8',
          Uint8Array.from(der),
          { name: 'Ed25519' },
          false,
          ['sign'],
        );
        const signature = new Uint8Array(
          await crypto.subtle.sign(
            'Ed25519',
            nativeKey,
            Uint8Array.from(bytes),
          ),
        );
        const encoded = btoa(String.fromCharCode(...signature))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
        const nativeAccepted = PrivateGenesisSignature.verify(
          JSON.stringify({
            ...JSON.parse(unsigned),
            signatures: { [owner]: encoded },
          }),
          owner,
          scope,
          context,
        );
        let wrongOwnerRejected = false;
        let wrongScopeRejected = false;
        let duplicateRejected = false;
        try {
          PrivateGenesisSignature.verify(
            signed,
            'A'.repeat(43),
            scope,
            context,
          );
        } catch (error) {
          wrongOwnerRejected = error.message === 'Invalid private genesis';
        }
        try {
          PrivateGenesisSignature.verify(
            signed,
            owner,
            'A'.repeat(43),
            context,
          );
        } catch (error) {
          wrongScopeRejected = error.message === 'Invalid private genesis';
        }
        try {
          PrivateGenesisSignature.verify(
            signed.replace('"version":1', '"version":2,"version":1'),
            owner,
            scope,
            context,
          );
        } catch (error) {
          duplicateRejected = error.message === 'Invalid private genesis';
        }
        return {
          accepted,
          generated,
          nativeAccepted,
          wrongOwnerRejected,
          wrongScopeRejected,
          duplicateRejected,
        };
      },
      {
        signed,
        unsigned: canonicalize(unsigned),
        pem: key.export({ format: 'pem', type: 'pkcs8' }).toString(),
        owner,
        scope: head.scopeId,
        context: head.mlsContextHash,
        bytes: [...bytes],
        der: [...der],
      },
    );
    assert.deepEqual(result, {
      accepted: signed,
      generated: signed,
      nativeAccepted: signed,
      wrongOwnerRejected: true,
      wrongScopeRejected: true,
      duplicateRejected: true,
    });
    console.log(
      'PASS native Node, native WebCrypto and bundled Chromium agree on genesis signatures; untrusted owner, wrong scope and ambiguous JSON are rejected.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
