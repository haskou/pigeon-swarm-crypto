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
const { PrivateControlSignature } = require('../../dist');

(async () => {
  const ders = [7, 8, 9].map((byte) =>
    Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.alloc(32, byte),
    ]),
  );
  const keys = ders.map((key) =>
    createPrivateKey({ key, format: 'der', type: 'pkcs8' }),
  );
  const owners = keys.map((key) =>
    createPublicKey(key)
      .export({ format: 'der', type: 'spki' })
      .subarray(-32)
      .toString('base64url'),
  );
  const encoded = (byte) => Buffer.alloc(32, byte).toString('base64url');
  const hash = (value) =>
    createHash('sha256').update(canonicalize(value)).digest('base64url');
  const policy = {
    version: 1,
    devices: owners.map((deviceKey, i) => ({
      deviceKey,
      mlsCredentialHash: encoded(i + 20),
    })),
    authorityKeys: owners,
    threshold: 2,
    sequencerKey: owners[0],
    freshnessAuthorityKey: owners[1],
    leaseRevocationKey: owners[0],
    leaseRevocationHpkeKey: encoded(5),
  };
  const checkpoint = {
    scopeId: encoded(1),
    revision: 3,
    headHash: encoded(2),
    mlsEpoch: 3,
    policy,
  };
  const nextPolicy = {
    ...policy,
    authorityKeys: [owners[2]],
    threshold: 1,
    sequencerKey: owners[2],
  };
  const messageHash = encoded(4);
  const contextHash = encoded(3);
  const head = {
    scopeId: checkpoint.scopeId,
    revision: 4,
    parentHeadHash: checkpoint.headHash,
    mlsEpoch: 4,
    mlsContextHash: contextHash,
    policyHash: hash(nextPolicy),
  };
  const unsigned = {
    ...head,
    headHash: hash(head),
    mlsMessageHash: messageHash,
    policy: nextPolicy,
  };
  const bytes = Buffer.from(
    'pigeon.private-control.v1\0' + canonicalize(unsigned),
  );
  const signed = canonicalize({
    ...unsigned,
    signatures: Object.fromEntries(
      [0, 1].map((i) => [
        owners[i],
        sign(null, bytes, keys[i]).toString('base64url'),
      ]),
    ),
  });
  const checkpointJson = JSON.stringify(checkpoint);
  assert.equal(
    PrivateControlSignature.verify(
      signed,
      checkpointJson,
      messageHash,
      contextHash,
    ),
    signed,
  );
  const bundle = await build({
    stdin: {
      contents: "export { PrivateControlSignature } from './dist/index.js';",
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
      '<!doctype html><title>Disposable control interoperability test</title>',
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
      async ({
        signed,
        checkpointJson,
        messageHash,
        contextHash,
        owners,
        ders,
        bytes,
        unsigned,
      }) => {
        const { PrivateControlSignature } = PigeonCrypto;
        const authenticated = PrivateControlSignature.authenticate(
          signed,
          checkpointJson,
          messageHash,
        );
        const accepted = PrivateControlSignature.verify(
          signed,
          checkpointJson,
          messageHash,
          contextHash,
        );
        const nativeSignatures = await Promise.all(
          ders.map(async (der, i) => {
            const key = await crypto.subtle.importKey(
              'pkcs8',
              Uint8Array.from(der),
              { name: 'Ed25519' },
              false,
              ['sign'],
            );
            const signature = new Uint8Array(
              await crypto.subtle.sign('Ed25519', key, Uint8Array.from(bytes)),
            );
            return [
              owners[i],
              btoa(String.fromCharCode(...signature))
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, ''),
            ];
          }),
        );
        const nativeRecord = (indices) =>
          JSON.stringify({
            ...unsigned,
            signatures: Object.fromEntries(
              indices.map((i) => nativeSignatures[i]),
            ),
          });
        const nativeAccepted = PrivateControlSignature.verify(
          nativeRecord([0, 1]),
          checkpointJson,
          messageHash,
          contextHash,
        );
        const rejected = [nativeRecord([2]), nativeRecord([1, 2])].map(
          (record) => {
            try {
              PrivateControlSignature.authenticate(
                record,
                checkpointJson,
                messageHash,
              );
              return false;
            } catch (error) {
              return error.message === 'Invalid private control';
            }
          },
        );
        return { authenticated, accepted, nativeAccepted, rejected };
      },
      {
        signed,
        checkpointJson,
        messageHash,
        contextHash,
        owners,
        ders: ders.map((der) => [...der]),
        bytes: [...bytes],
        unsigned,
      },
    );
    assert.deepEqual(result, {
      authenticated: signed,
      accepted: signed,
      nativeAccepted: signed,
      rejected: [true, true],
    });
    console.log(
      'PASS Node, Chromium and native WebCrypto agree on control quorum; self-authorized replacement and missing previous sequencer are rejected.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
