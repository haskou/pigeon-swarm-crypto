const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const Crypto = require('../../dist');
const network = require('../../vectors/private-network.json');
const relays = require('../../vectors/relay-records.json');
const turn = require('../../vectors/turn-credentials.json');

const check = (Crypto, vectors) => {
  const { network, relays, turn } = vectors;
  const keys = {
    network: Crypto.PrivateKey.fromPEM(network.keys.network.privateKeyPem),
    other: Crypto.PrivateKey.fromPEM(network.keys.other.privateKeyPem),
  };
  const rejects = (operation, message) => {
    try {
      operation();
    } catch (error) {
      return error.message === message;
    }
    return false;
  };
  const { networkId, topic } = network.pubsub;
  const sealed = Crypto.PrivateNetworkPubSubEnvelope.seal(
    keys.network,
    networkId,
    topic,
    network.pubsub.payload,
  );

  return {
    fingerprint: Crypto.PrivateNetworkKeys.fingerprint(keys.network),
    relayLookupKey: Crypto.PrivateNetworkKeys.relayLookupKey(keys.network),
    swarmKey: new TextDecoder().decode(
      Crypto.PrivateNetworkKeys.swarmKey(keys.network),
    ),
    pubsub: Crypto.PrivateNetworkPubSubEnvelope.open(
      keys.network,
      networkId,
      topic,
      network.pubsub.envelope,
    ),
    sealedRoundTrip: Crypto.PrivateNetworkPubSubEnvelope.open(
      keys.network,
      networkId,
      topic,
      sealed,
    ),
    sealed,
    pubsubRejected: network.pubsub.invalid.every((entry) =>
      rejects(
        () =>
          Crypto.PrivateNetworkPubSubEnvelope.open(
            keys[entry.key],
            entry.networkId,
            entry.topic,
            entry.envelope,
          ),
        'Invalid private network message',
      ),
    ),
    relayRecord: Crypto.PrivateNetworkRelayRecordEnvelope.open(
      keys.network,
      network.relayRecord.envelope,
    ),
    relayRejected: network.relayRecord.invalid.every((entry) =>
      rejects(
        () =>
          Crypto.PrivateNetworkRelayRecordEnvelope.open(
            keys[entry.key],
            entry.envelope,
          ),
        'Invalid private network relay record',
      ),
    ),
    credentials: turn.credentials.map((entry) =>
      Crypto.TurnRestCredential.issue(
        entry.sharedSecret,
        entry.expiresAtSeconds,
        entry.user,
      ),
    ),
    subjects: turn.peerSubjects.map((entry) =>
      Crypto.TurnRestCredential.peerSubject(entry.sharedSecret, entry.peerId),
    ),
    turnRejected: turn.invalidCredentials.every((entry) =>
      rejects(
        () =>
          Crypto.TurnRestCredential.issue(
            entry.sharedSecret,
            entry.expiresAtSeconds,
            entry.user,
          ),
        'Invalid TURN credential',
      ),
    ),
    subjectRejected: turn.invalidPeerSubjects.every((entry) =>
      rejects(
        () =>
          Crypto.TurnRestCredential.peerSubject(
            entry.sharedSecret,
            entry.peerId,
          ),
        'Invalid TURN credential',
      ),
    ),
    callPoolSignatures: relays.cases.map((entry) =>
      Crypto.CallRelayRecordSignature.poolSignature(
        entry.derived.record,
        relays.sharedSecret,
      ),
    ),
    callVerified: relays.cases.every(
      (entry) =>
        Crypto.CallRelayRecordSignature.verify(
          entry.derived.record,
          entry.derived.record.poolSignature,
          entry.derived.record.signature,
          relays.sharedSecret,
        ) === undefined,
    ),
    callRejected: relays.invalidCallRecords.every((entry) =>
      rejects(
        () =>
          Crypto.CallRelayRecordSignature.verify(
            entry.record,
            entry.record.poolSignature,
            entry.record.signature,
            entry.sharedSecret,
          ),
        'Invalid call relay record',
      ),
    ),
    publicVerified:
      Crypto.PublicRelayRecordSignature.verify(
        relays.publicRelay.record,
        relays.publicRelay.record.signature,
      ) === undefined,
    publicRejected: relays.publicRelay.invalid.every((entry) =>
      rejects(
        () =>
          Crypto.PublicRelayRecordSignature.verify(
            entry.record,
            entry.record.signature,
          ),
        'Invalid public relay record',
      ),
    ),
    rawPublicKey: [
      ...Crypto.PrivateKey.fromSeed(
        Uint8Array.from(
          network.keys.network.seedHex
            .match(/../g)
            .map((byte) => parseInt(byte, 16)),
        ),
      )
        .getPublicKey()
        .toRaw(),
    ],
  };
};

const expectation = {
  fingerprint: network.derived.fingerprint,
  relayLookupKey: network.derived.relayLookupKey,
  swarmKey: network.derived.swarmKey,
  pubsub: network.pubsub.payload,
  sealedRoundTrip: network.pubsub.payload,
  pubsubRejected: true,
  relayRecord: network.relayRecord.record,
  relayRejected: true,
  credentials: turn.credentials.map(({ credential, username }) => ({
    credential,
    username,
  })),
  subjectRejected: true,
  subjects: turn.peerSubjects.map((entry) => entry.subject),
  turnRejected: true,
  callPoolSignatures: relays.cases.map((entry) => entry.derived.poolSignature),
  callVerified: true,
  callRejected: true,
  publicVerified: true,
  publicRejected: true,
  rawPublicKey: [
    ...Crypto.PrivateKey.fromPEM(network.keys.network.privateKeyPem)
      .getPublicKey()
      .toRaw(),
  ],
};

(async () => {
  const vectors = { network, relays, turn };
  const { sealed, ...nodeResult } = check(Crypto, vectors);
  assert.deepEqual(nodeResult, expectation);
  assert.notEqual(sealed, network.pubsub.envelope);

  const bundle = await build({
    stdin: {
      contents: "export * from './dist/index.js';",
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
      '<!doctype html><title>Disposable network derivation interoperability test</title>',
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
      async ({ checkSource, vectors }) => {
        const { network, turn } = vectors;
        const check = new Function(`return (${checkSource})`)();
        const { sealed, ...libraryResult } = check(PigeonCrypto, vectors);
        const hex = (value) =>
          Uint8Array.from(value.match(/../g).map((byte) => parseInt(byte, 16)));
        const fromBase64Url = (value) =>
          Uint8Array.from(
            atob(value.replace(/-/g, '+').replace(/_/g, '/')),
            (character) => character.charCodeAt(0),
          );
        const hkdf = async (label) => {
          const material = await crypto.subtle.importKey(
            'raw',
            hex(network.keys.network.seedHex),
            'HKDF',
            false,
            ['deriveBits'],
          );
          return new Uint8Array(
            await crypto.subtle.deriveBits(
              {
                name: 'HKDF',
                hash: 'SHA-256',
                salt: new Uint8Array(),
                info: new TextEncoder().encode(label),
              },
              material,
              256,
            ),
          );
        };
        const toHex = (bytes) =>
          [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
        const pubsubKey = await crypto.subtle.importKey(
          'raw',
          await hkdf(network.labels.pubsub),
          'AES-GCM',
          false,
          ['decrypt'],
        );
        const parsed = JSON.parse(sealed);
        const nativeOpened = new TextDecoder().decode(
          await crypto.subtle.decrypt(
            {
              name: 'AES-GCM',
              iv: fromBase64Url(parsed.nonce),
              additionalData: new TextEncoder().encode(network.pubsub.aad),
            },
            pubsubKey,
            fromBase64Url(parsed.ciphertext),
          ),
        );
        const turnKey = await crypto.subtle.importKey(
          'raw',
          new TextEncoder().encode(turn.credentials[0].sharedSecret),
          { name: 'HMAC', hash: 'SHA-1' },
          false,
          ['sign'],
        );
        const nativeCredential = btoa(
          String.fromCharCode(
            ...new Uint8Array(
              await crypto.subtle.sign(
                'HMAC',
                turnKey,
                new TextEncoder().encode(turn.credentials[0].username),
              ),
            ),
          ),
        );
        return {
          libraryResult,
          nativeOpened,
          nativeCredential,
          pubsubKeyHex: toHex(await hkdf(network.labels.pubsub)),
          relayKeyHex: toHex(await hkdf(network.labels.relayRecord)),
          swarmPskHex: toHex(await hkdf(network.labels.swarmPsk)),
        };
      },
      { checkSource: check.toString(), vectors },
    );
    assert.deepEqual(result, {
      libraryResult: expectation,
      nativeOpened: network.pubsub.payload,
      nativeCredential: turn.credentials[0].credential,
      pubsubKeyHex: network.derived.pubsubKeyHex,
      relayKeyHex: network.derived.relayRecordKeyHex,
      swarmPskHex: network.derived.swarmPskHex,
    });
    console.log(
      'PASS Node, Chromium and native WebCrypto agree on private network keys, sealed envelopes, TURN credentials and relay record signatures; every negative vector is rejected.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
