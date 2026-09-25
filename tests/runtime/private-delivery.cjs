const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');
const { createHash } = require('node:crypto');

const {
  AuthenticatedPrivateDeliverySchedule,
  MlsDeviceIdentity,
  PrivateDeliveryEnvelope,
  PrivateDeliveryFrame,
  PrivateDeliveryKeySchedule,
} = require('../../dist/mls/index.cjs');
const { UserRootKey } = require('../../dist');

const bytes = (value) => new TextEncoder().encode(value);

const run = async () => {
  const vectors = JSON.parse(
    await readFile(
      'tests/fixtures/private-delivery-vectors.json',
      'utf8',
    ),
  );
  const framing = vectors.hpkeFraming;
  const synthetic = PrivateDeliveryFrame.application(Uint8Array.of(1, 2, 3, 4));
  const plaintext = PrivateDeliveryEnvelope.framePlaintext(
    synthetic,
    framing.header.bucketBytes,
  );

  assert.equal(synthetic.toCanonicalJson(), framing.frameJcs);
  assert.equal(plaintext.length, framing.header.bucketBytes - 32 - 16);
  assert.equal(
    Buffer.from(plaintext.subarray(0, 4)).toString('hex'),
    framing.lengthPrefixHex,
  );
  assert.equal(
    createHash('sha256').update(plaintext).digest('hex'),
    framing.plaintextSha256Hex,
  );
  assert.equal(
    PrivateDeliveryEnvelope.headerAad(framing.header),
    framing.aadJcs,
  );

  const now = Date.UTC(2026, 8, 25, 14, 30);
  const retentionMs = 3 * 24 * 60 * 60 * 1000;
  const root = UserRootKey.generate();
  let schedule = await PrivateDeliveryKeySchedule.generate(
    now,
    7,
    retentionMs,
  );
  assert.equal(schedule.descriptors.length, 8);
  assert.equal(new Set(schedule.descriptors.map((value) => value.mailboxId)).size, 8);
  assert.equal(
    new Set(schedule.descriptors.map((value) => value.recipientPublicKey)).size,
    8,
  );
  assert.ok(
    schedule.descriptors.every((value) => value.authorizationRevision === 7),
  );
  assert.equal(JSON.stringify(schedule), '{}');

  const identity = await MlsDeviceIdentity.generate(bytes('recipient-device'));
  const authenticated = await identity.authenticateDeliverySchedule(
    schedule.descriptors,
  );
  const verified = await AuthenticatedPrivateDeliverySchedule.verify(
    authenticated.valueOf(),
    identity.credential,
    7,
  );
  assert.equal(verified.descriptors.length, 8);
  const impostor = await MlsDeviceIdentity.generate(bytes('impostor-device'));
  await assert.rejects(() =>
    AuthenticatedPrivateDeliverySchedule.verify(
      authenticated.valueOf(),
      impostor.credential,
      7,
    ),
  );

  const descriptor = schedule.descriptorFor(now);
  const otherSchedule = await PrivateDeliveryKeySchedule.generate(
    now,
    7,
    retentionMs,
  );
  const otherDescriptor = otherSchedule.descriptorFor(now);
  const deliveryJoinPackage = await identity.createJoinPackage();
  assert.notDeepEqual(
    Buffer.from(descriptor.recipientPublicKey, 'base64url'),
    identity.credential.signaturePublicKey,
  );
  assert.notDeepEqual(
    Buffer.from(descriptor.recipientPublicKey, 'base64url'),
    deliveryJoinPackage.initPublicKey,
  );
  assert.notDeepEqual(
    Buffer.from(descriptor.recipientPublicKey, 'base64url'),
    deliveryJoinPackage.leafPublicKey,
  );
  const substituted = authenticated
    .valueOf()
    .replace(schedule.descriptors[0].mailboxId, otherDescriptor.mailboxId);
  await assert.rejects(() =>
    AuthenticatedPrivateDeliverySchedule.verify(
      substituted,
      identity.credential,
      7,
    ),
  );
  const application = PrivateDeliveryFrame.application(bytes('private message'));
  const expiresAt = descriptor.writeValidUntil + retentionMs;
  const envelope = await PrivateDeliveryEnvelope.seal(
    application,
    descriptor,
    now,
    expiresAt,
    4096,
  );
  const secondCopy = await PrivateDeliveryEnvelope.seal(
    application,
    otherDescriptor,
    now,
    expiresAt,
    4096,
  );
  assert.equal(Buffer.from(envelope.ciphertext, 'base64').length, 4096);
  assert.notEqual(envelope.ciphertext, secondCopy.ciphertext);
  assert.equal(JSON.stringify(envelope).includes('private message'), false);

  const opened = await schedule.open(envelope, now);
  assert.equal(opened.kind, 'mls-application');
  assert.deepEqual(opened.mlsMessage, bytes('private message'));
  await assert.rejects(() => otherSchedule.open(envelope, now));
  for (const frame of [
    PrivateDeliveryFrame.commit(bytes('commit bytes')),
    PrivateDeliveryFrame.welcome(bytes('welcome bytes')),
  ]) {
    const framedEnvelope = await PrivateDeliveryEnvelope.seal(
      frame,
      descriptor,
      now,
      expiresAt,
      4096,
    );
    const openedFrame = await schedule.open(framedEnvelope, now);
    assert.equal(openedFrame.kind, frame.kind);
    assert.deepEqual(openedFrame.mlsMessage, frame.mlsMessage);
  }

  for (const field of ['mailboxId', 'deliveryId', 'expiresAt', 'bucketBytes']) {
    const tampered = { ...envelope, [field]: envelope[field] };
    if (field === 'mailboxId') tampered[field] = otherDescriptor.mailboxId;
    if (field === 'deliveryId') tampered[field] = 'AwMDAwMDAwMDAwMDAwMDAw';
    if (field === 'expiresAt') tampered[field] -= 1;
    if (field === 'bucketBytes') tampered[field] = 16384;
    await assert.rejects(() => schedule.open(tampered, now));
  }
  const corrupted = { ...envelope };
  const corruptedWire = Buffer.from(corrupted.ciphertext, 'base64');
  corruptedWire[corruptedWire.length - 1] ^= 1;
  corrupted.ciphertext = corruptedWire.toString('base64');
  await assert.rejects(() => schedule.open(corrupted, now));

  const protectedSchedule = schedule.protect(root);
  const scheduleCommitment = schedule.commitment;
  schedule.destroy();
  schedule = await PrivateDeliveryKeySchedule.restore(
    protectedSchedule,
    root,
    scheduleCommitment,
  );
  await assert.rejects(() =>
    PrivateDeliveryKeySchedule.restore(
      protectedSchedule,
      UserRootKey.generate(),
      scheduleCommitment,
    ),
  );
  await assert.rejects(() =>
    PrivateDeliveryKeySchedule.restore(
      protectedSchedule,
      root,
      'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    ),
  );
  const restored = await schedule.open(envelope, now);
  assert.deepEqual(restored.mlsMessage, bytes('private message'));

  const lastMinute = descriptor.writeValidUntil - 1;
  const lateEnvelope = await PrivateDeliveryEnvelope.seal(
    application,
    descriptor,
    lastMinute,
    descriptor.writeValidUntil + retentionMs,
    4096,
  );
  assert.deepEqual(
    (await schedule.open(lateEnvelope, descriptor.writeValidUntil + retentionMs)).mlsMessage,
    bytes('private message'),
  );
  await assert.rejects(() =>
    schedule.open(lateEnvelope, descriptor.writeValidUntil + retentionMs + 1),
  );
  schedule = schedule.retire(descriptor.writeValidUntil + retentionMs + 1);
  await assert.rejects(() => schedule.open(lateEnvelope, now));

  const futureDescriptor = schedule.descriptors[0];
  const futureEnvelope = await PrivateDeliveryEnvelope.seal(
    application,
    futureDescriptor,
    futureDescriptor.validFrom,
    futureDescriptor.writeValidUntil,
    4096,
  );
  const futureMailbox = futureDescriptor.mailboxId;
  schedule = schedule.revoke([futureMailbox]);
  assert.equal(schedule.descriptors.some((value) => value.mailboxId === futureMailbox), false);
  await assert.rejects(() => schedule.open(futureEnvelope, futureDescriptor.validFrom));

  assert.throws(() => PrivateDeliveryFrame.fromCanonicalJson('{"kind":"unknown"}'));
  assert.throws(() =>
    PrivateDeliveryFrame.fromCanonicalJson(
      '{"kind":"mls-application","mlsMessage":"AQ==","version":2}',
    ),
  );
  assert.throws(() => PrivateDeliveryEnvelope.headerAad({ ...framing.header, version: 2 }));

  identity.destroy();
  impostor.destroy();

  console.log('PASS recipient HPKE delivery, framing vector, daily rotation, retention and revocation.');
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
