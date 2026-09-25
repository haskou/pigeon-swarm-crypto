const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');
const { createServer } = require('node:http');
const { chromium } = require('playwright');
const {
  PrivateDeliveryEnvelope,
  PrivateDeliveryDescriptor,
  PrivateDeliveryFrame,
} = require('../../dist/mls/index.cjs');

(async () => {
  const bundle = await readFile('dist/mls/index.mjs');
  const server = createServer((request, response) => {
    if (request.url === '/mls.mjs') {
      response.setHeader('Content-Type', 'text/javascript');
      response.end(bundle);
      return;
    }
    response.setHeader('Content-Type', 'text/html');
    response.end('<!doctype html><title>MLS runtime test</title>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;

  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto('http://127.0.0.1:' + server.address().port);
    const now = Date.UTC(2026, 8, 25, 12);
    const browserDelivery = await page.evaluate(async (timestamp) => {
      const { PrivateDeliveryKeySchedule, UserRootKey } = await import('/mls.mjs');
      const root = UserRootKey.generate();
      const schedule = await PrivateDeliveryKeySchedule.generate(
        timestamp,
        4,
        24 * 60 * 60 * 1000,
      );

      return {
        descriptor: schedule.descriptorFor(timestamp).toJSON(),
        commitment: schedule.commitment,
        protectedSchedule: schedule.protect(root).valueOf(),
        rootKey: root.valueOf(),
      };
    }, now);
    const deliveryDescriptor = PrivateDeliveryDescriptor.from(
      browserDelivery.descriptor,
    );
    const nodeEnvelope = await PrivateDeliveryEnvelope.seal(
      PrivateDeliveryFrame.application(new TextEncoder().encode('node to browser')),
      deliveryDescriptor,
      now,
      deliveryDescriptor.writeValidUntil,
      4096,
    );
    const result = await page.evaluate(async (delivery) => {
      const {
        MlsDeviceIdentity,
        MlsGroupSession,
        UserRootKey,
        PrivateDeliveryKeySchedule,
        ProtectedPrivateDeliveryKeySchedule,
      } = await import('/mls.mjs');
      const text = new TextEncoder();
      const read = new TextDecoder();
      const key = (bytes) => {
        let binary = '';
        bytes.forEach((byte) => {
          binary += String.fromCharCode(byte);
        });
        return btoa(binary);
      };
      const aliceIdentity = await MlsDeviceIdentity.generate(
        text.encode('browser-alice'),
      );
      const bobIdentity = await MlsDeviceIdentity.generate(
        text.encode('browser-bob'),
      );
      const trusted = new Map(
        [aliceIdentity, bobIdentity].map((identity) => [
          key(identity.credential.identity),
          key(identity.credential.signaturePublicKey),
        ]),
      );
      const verify = ({ identity, signaturePublicKey }) =>
        trusted.get(key(identity)) === key(signaturePublicKey);
      const alicePackage = await aliceIdentity.createJoinPackage();
      const bobPackage = await bobIdentity.createJoinPackage();
      let alice = await MlsGroupSession.create(
        text.encode('browser-group'),
        alicePackage,
        verify,
      );
      const added = await alice.addMembers([bobPackage.publicBytes]);
      alice = added.session;
      let bob = await MlsGroupSession.join(
        added.welcome,
        bobPackage,
        verify,
      );
      const root = UserRootKey.generate();
      bob = MlsGroupSession.restore(bob.protectState(root), root, verify, 1n);
      const encrypted = await alice.encrypt(text.encode('browser secret'));
      alice = encrypted.session;
      const decrypted = await bob.decrypt(encrypted.frame);
      bob = decrypted.session;
      const refreshed = await alice.refresh();
      bob = await bob.applyCommit(refreshed.commit);
      const restoredDeliverySchedule = await PrivateDeliveryKeySchedule.restore(
        new ProtectedPrivateDeliveryKeySchedule(delivery.protectedSchedule),
        UserRootKey.fromBase64(delivery.rootKey),
        delivery.commitment,
      );
      const openedDelivery = await restoredDeliverySchedule.open(
        delivery.envelope,
        delivery.now,
      );

      return {
        active: bob.active,
        epoch: bob.epoch.toString(),
        plaintext: read.decode(decrypted.plaintext),
        transportPlaintext: read.decode(openedDelivery.mlsMessage),
      };
    }, {
      envelope: nodeEnvelope,
      commitment: browserDelivery.commitment,
      now,
      protectedSchedule: browserDelivery.protectedSchedule,
      rootKey: browserDelivery.rootKey,
    });

    assert.deepEqual(result, {
      active: true,
      epoch: '2',
      plaintext: 'browser secret',
      transportPlaintext: 'node to browser',
    });
    console.log(
      'PASS Chromium MLS lifecycle and Node-to-browser recipient HPKE delivery.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
