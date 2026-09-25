const assert = require('node:assert/strict');

const {
  AuthenticatedPrivateDeliverySchedule,
  InvalidMlsFrameError,
  InvalidMlsStateError,
  InvalidPrivateDeliveryError,
  MlsApplicationFrame,
  MlsCommitFrame,
  MlsDeviceIdentity,
  MlsGroupSession,
  MlsJoinPackage,
  MlsWelcomeFrame,
  PrivateDeliveryDescriptor,
  PrivateDeliveryEnvelope,
  PrivateDeliveryFrame,
  PrivateDeliveryKeySchedule,
  ProtectedMlsDeviceIdentity,
  ProtectedMlsGroupState,
  ProtectedMlsJoinPackage,
  ProtectedPrivateDeliveryKeySchedule,
  UserRootKey,
} = require('../../dist/mls/index.cjs');
const {
  BinarySecretCodec,
} = require('../../dist/mls/internal/BinarySecretCodec.js');
const {
  DeliveryBase64Url,
} = require('../../dist/mls/internal/DeliveryBase64Url.js');
const MlsCodec = require('../../dist/mls/internal/MlsCodec.js');
const {
  decodeMessage,
  decodePublicKeyPackage,
  decodeState,
} = MlsCodec;
const {
  RootProtectedEnvelope,
} = require('../../dist/mls/internal/RootProtectedEnvelope.js');
const {
  getMlsCiphersuite,
} = require('../../dist/mls/internal/MlsRuntime.js');
const {
  acceptsMlsMemberCount,
  requireMlsWelcome,
  validateMlsCredential,
} = require('../../dist/mls/internal/MlsProtocolPolicy.js');
const canonicalize = require('canonicalize');

const text = new TextEncoder();
const bytes = (value) => text.encode(value);
const expectInvalid = (callback) => assert.throws(callback);
const expectInvalidAsync = (callback) => assert.rejects(callback);

const replacePart = (serialized, index, value) => {
  const parts = serialized.split('.');
  parts[index] = value;
  return parts.join('.');
};

const run = async () => {
  assert.equal(typeof InvalidMlsFrameError, 'function');
  assert.equal(typeof InvalidMlsStateError, 'function');
  assert.equal(typeof InvalidPrivateDeliveryError, 'function');
  assert.equal(typeof MlsCodec.encodeGroupContext, 'function');
  const root = UserRootKey.generate();
  const nullRoot = new UserRootKey();

  expectInvalid(() => BinarySecretCodec.encode([], 32));
  expectInvalid(() => BinarySecretCodec.encode([new Uint8Array()], 32));
  expectInvalid(() => BinarySecretCodec.encode([bytes('too large')], 5));
  expectInvalid(() => BinarySecretCodec.decode(new Uint8Array(), 1, 32));
  expectInvalid(() =>
    BinarySecretCodec.decode(Uint8Array.of(0x50, 0x53, 0x42, 0x01, 1), 1, 32),
  );
  expectInvalid(() =>
    BinarySecretCodec.decode(
      Uint8Array.of(0x50, 0x53, 0x42, 0x01, 1, 0, 0, 0),
      1,
      32,
    ),
  );
  expectInvalid(() =>
    BinarySecretCodec.decode(
      Uint8Array.of(0x50, 0x53, 0x42, 0x01, 1, 0, 0, 0, 2, 1),
      1,
      32,
    ),
  );
  const encodedPart = BinarySecretCodec.encode([bytes('a')], 32);
  expectInvalid(() =>
    BinarySecretCodec.decode(
      Uint8Array.from([...encodedPart, 0]),
      1,
      32,
    ),
  );

  expectInvalid(() => DeliveryBase64Url.decode(null, 32));
  expectInvalid(() => DeliveryBase64Url.decode(`${'A'.repeat(42)}B`, 32));
  expectInvalid(() => DeliveryBase64Url.decodeAtMost('', 32));
  expectInvalid(() => DeliveryBase64Url.decodeAtMost('A'.repeat(44), 32));
  expectInvalid(() => DeliveryBase64Url.decodeAtMost('AB', 32));

  expectInvalid(() => decodeMessage(new Uint8Array()));
  expectInvalid(() => decodeMessage(Uint8Array.of(0, 1, 2, 3)));
  expectInvalid(() => decodeMessage(null));
  expectInvalid(() => decodeState(new Uint8Array()));
  expectInvalid(() => decodeState(Uint8Array.of(0, 1, 2, 3)));

  expectInvalid(() => RootProtectedEnvelope.protect(new Uint8Array(), root, 'domain', 8));
  expectInvalid(() => RootProtectedEnvelope.protect(bytes('123456789'), root, 'domain', 8));
  expectInvalid(() => RootProtectedEnvelope.protect(bytes('secret'), nullRoot, 'domain', 8));
  const protectedSecret = RootProtectedEnvelope.protect(
    bytes('secret'),
    root,
    'domain',
    8,
  );
  expectInvalid(() => RootProtectedEnvelope.validate(null, 8));
  expectInvalid(() => RootProtectedEnvelope.validate('x'.repeat(17), 8));
  expectInvalid(() => RootProtectedEnvelope.validate('v1.bad.header', 8));
  expectInvalid(() =>
    RootProtectedEnvelope.validate(replacePart(protectedSecret, 3, '!!!!'), 8),
  );
  expectInvalid(() =>
    RootProtectedEnvelope.validate(replacePart(protectedSecret, 6, ''), 8),
  );
  expectInvalid(() => RootProtectedEnvelope.unlock(protectedSecret, root, 'other', 8));
  expectInvalid(() => RootProtectedEnvelope.unlock(protectedSecret, nullRoot, 'domain', 8));
  const oversizedCiphertext = [
    'v1',
    'hkdf-sha256',
    'aes-256-gcm',
    Buffer.alloc(16).toString('base64'),
    Buffer.alloc(12).toString('base64'),
    Buffer.alloc(16).toString('base64'),
    Buffer.alloc(4097).toString('base64'),
  ].join('.');
  expectInvalid(() => RootProtectedEnvelope.validate(oversizedCiphertext, 4096));
  expectInvalid(() =>
    RootProtectedEnvelope.validate(
      replacePart(
        protectedSecret,
        3,
        `${'A'.repeat(21)}B==`,
      ),
      8,
    ),
  );
  const paddedCiphertextEnvelope = RootProtectedEnvelope.protect(
    bytes('abcde'),
    root,
    'domain',
    4096,
  );
  const paddedCiphertextParts = paddedCiphertextEnvelope.split('.');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const finalContentIndex = paddedCiphertextParts[6].length - 2;
  const finalCharacterIndex = alphabet.indexOf(
    paddedCiphertextParts[6][finalContentIndex],
  );
  paddedCiphertextParts[6] = `${paddedCiphertextParts[6].slice(0, finalContentIndex)}${alphabet[finalCharacterIndex + 1]}=`;
  expectInvalid(() =>
    RootProtectedEnvelope.validate(paddedCiphertextParts.join('.'), 4096),
  );

  for (const Frame of [MlsApplicationFrame, MlsCommitFrame, MlsWelcomeFrame]) {
    expectInvalid(() => Frame.create(new Uint8Array()));
    expectInvalid(() => Frame.create(new Uint8Array(1024 * 1024 + 1)));
    expectInvalid(() => Frame.fromBytes(new Uint8Array()));
  }
  const welcomeRoundTrip = MlsWelcomeFrame.create(bytes('welcome'));
  assert.deepEqual(
    MlsWelcomeFrame.fromBytes(welcomeRoundTrip.toBytes()).payloadBytes(),
    bytes('welcome'),
  );

  await expectInvalidAsync(() => MlsDeviceIdentity.generate(new Uint8Array()));
  await expectInvalidAsync(() => MlsDeviceIdentity.generate(new Uint8Array(1025)));
  const destroyedIdentity = await MlsDeviceIdentity.generate(bytes('destroyed'));
  destroyedIdentity.destroy();
  expectInvalid(() => destroyedIdentity.credential);
  await expectInvalidAsync(() => destroyedIdentity.createJoinPackage());
  await expectInvalidAsync(() => destroyedIdentity.authenticateDeliverySchedule([]));
  expectInvalid(() => destroyedIdentity.protect(root));

  const malformedIdentityState = RootProtectedEnvelope.protect(
    BinarySecretCodec.encode([bytes('identity'), new Uint8Array(31), new Uint8Array(48)], 4096),
    root,
    'pigeon.mls-device-identity-protection.v1',
    4096,
  );
  await expectInvalidAsync(() =>
    MlsDeviceIdentity.restore(
      new ProtectedMlsDeviceIdentity(malformedIdentityState),
      root,
    ),
  );
  const mismatchedIdentityState = RootProtectedEnvelope.protect(
    BinarySecretCodec.encode([bytes('identity'), new Uint8Array(32), new Uint8Array(48)], 4096),
    root,
    'pigeon.mls-device-identity-protection.v1',
    4096,
  );
  await expectInvalidAsync(() =>
    MlsDeviceIdentity.restore(
      new ProtectedMlsDeviceIdentity(mismatchedIdentityState),
      root,
    ),
  );

  const founderIdentity = await MlsDeviceIdentity.generate(bytes('founder-validation'));
  const founderPackage = await founderIdentity.createJoinPackage();
  const trusted = async () => true;
  await expectInvalidAsync(() =>
    MlsGroupSession.create(new Uint8Array(), founderPackage, trusted),
  );
  const rejectedFounderPackage = await founderIdentity.createJoinPackage();
  await expectInvalidAsync(() =>
    MlsGroupSession.create(bytes('rejected'), rejectedFounderPackage, async () => false),
  );
  let founder = await MlsGroupSession.create(
    bytes('validation-group'),
    founderPackage,
    trusted,
  );
  await expectInvalidAsync(() => founder.addMembers([]));
  await expectInvalidAsync(() => founder.addMembers([new Uint8Array()]));
  await expectInvalidAsync(() => founder.addMembers([new Uint8Array(65537)]));
  const untrustedIdentity = await MlsDeviceIdentity.generate(bytes('untrusted'));
  const untrustedPackage = await untrustedIdentity.createJoinPackage();
  const verificationFounderPackage = await founderIdentity.createJoinPackage();
  const founderCredential = founderIdentity.credential;
  const founderIdentityKey = Buffer.from(founderCredential.identity).toString('base64');
  await expectInvalidAsync(() =>
    MlsGroupSession.create(
      bytes('verification-group'),
      verificationFounderPackage,
      async ({ identity }) => Buffer.from(identity).toString('base64') === founderIdentityKey,
    ).then((session) => {
      founder = session;
      return session.addMembers([untrustedPackage.publicBytes]);
    }),
  );
  const wrongWelcomePackage = await founderIdentity.createJoinPackage();
  const wrongWelcomeJoiner = await founderIdentity.createJoinPackage();
  await expectInvalidAsync(() =>
    MlsGroupSession.join(
      MlsWelcomeFrame.create(wrongWelcomePackage.publicBytes),
      wrongWelcomeJoiner,
      trusted,
    ),
  );
  await expectInvalidAsync(() =>
    founder.applyCommit(MlsCommitFrame.create(wrongWelcomePackage.publicBytes)),
  );
  await expectInvalidAsync(() => founder.removeMembers([]));
  await expectInvalidAsync(() => founder.removeMembers([new Uint8Array()]));
  await expectInvalidAsync(() =>
    founder.removeMembers([bytes('missing'), bytes('missing')]),
  );
  await expectInvalidAsync(() => founder.removeMembers([bytes('missing')]));
  await expectInvalidAsync(() => founder.encrypt(new Uint8Array()));
  await expectInvalidAsync(() => founder.encrypt(new Uint8Array(128 * 1024 + 1)));
  const invalidWelcomeJoinPackage = await founderIdentity.createJoinPackage();
  await expectInvalidAsync(() =>
    MlsGroupSession.join(
      MlsWelcomeFrame.create(MlsApplicationFrame.create(bytes('x')).payloadBytes()),
      invalidWelcomeJoinPackage,
      trusted,
    ),
  );
  expectInvalid(() =>
    MlsGroupSession.restore(
      founder.protectState(root),
      root,
      trusted,
      founder.epoch,
      'invalid',
    ),
  );
  const originalProcess = founder.process;
  founder.process = async () => ({ consumed: [], kind: 'newState' });
  await expectInvalidAsync(() =>
    founder.decrypt(MlsApplicationFrame.create(bytes('invalid-result'))),
  );
  founder.process = originalProcess;
  founder.process = async () => ({ consumed: [], kind: 'applicationMessage' });
  await expectInvalidAsync(() =>
    founder.applyCommit(MlsCommitFrame.create(bytes('invalid-result'))),
  );
  founder.process = originalProcess;
  expectInvalid(() => decodePublicKeyPackage(bytes('not a key package')));
  const deliveryIdentity = await MlsDeviceIdentity.generate(bytes('delivery-validation'));
  const deliveryPackage = await deliveryIdentity.createJoinPackage();
  const deliveryFounderPackage = await founderIdentity.createJoinPackage();
  const deliveryGroup = await MlsGroupSession.create(
    bytes('delivery-group'),
    deliveryFounderPackage,
    trusted,
  );
  const deliveryAddition = await deliveryGroup.addMembers([
    deliveryPackage.publicBytes,
  ]);
  expectInvalid(() => decodePublicKeyPackage(deliveryAddition.welcome.payloadBytes()));

  const protectedGroup = founder.protectState(root);
  assert.equal(typeof protectedGroup.valueOf(), 'string');
  const protectedIdentity = founderIdentity.protect(root);
  assert.equal(typeof protectedIdentity.valueOf(), 'string');
  const identityParts = BinarySecretCodec.decode(
    protectedIdentity.unlock(root),
    3,
    4096,
  );
  const mismatchedSignatureState = RootProtectedEnvelope.protect(
    BinarySecretCodec.encode(
      [
        identityParts[0],
        deliveryIdentity.credential.signaturePublicKey,
        identityParts[2],
      ],
      4096,
    ),
    root,
    'pigeon.mls-device-identity-protection.v1',
    4096,
  );
  await expectInvalidAsync(() =>
    MlsDeviceIdentity.restore(
      new ProtectedMlsDeviceIdentity(mismatchedSignatureState),
      root,
    ),
  );
  const protectedJoinPackage = (await founderIdentity.createJoinPackage()).protect(root);
  assert.equal(typeof protectedJoinPackage.valueOf(), 'string');
  const consumedPackage = await founderIdentity.createJoinPackage();
  consumedPackage.consumePrivatePackage();
  expectInvalid(() => consumedPackage.consumePrivatePackage());
  expectInvalid(() => consumedPackage.protect(root));
  const packageToCorrupt = await founderIdentity.createJoinPackage();
  const corruptedPackageState = RootProtectedEnvelope.protect(
    BinarySecretCodec.encode(
      [
        packageToCorrupt.publicBytes,
        Buffer.alloc(32, 3),
        Buffer.alloc(32, 4),
        identityParts[2],
      ],
      16384,
    ),
    root,
    'pigeon.mls-join-package-protection.v1',
    16384,
  );
  await expectInvalidAsync(() =>
    MlsJoinPackage.restore(
      new ProtectedMlsJoinPackage(corruptedPackageState),
      root,
    ),
  );
  const generatedPackage = await founderIdentity.createJoinPackage();
  const x509PublicPackage = generatedPackage.copyPublicPackage();
  x509PublicPackage.leafNode.credential = {
    certificates: [],
    credentialType: 'x509',
  };
  const x509Package = MlsJoinPackage.fromGenerated(
    x509PublicPackage,
    {
      hpkePrivateKey: new Uint8Array(32),
      initPrivateKey: new Uint8Array(32),
      signaturePrivateKey: new Uint8Array(48),
    },
  );
  expectInvalid(() => x509Package.credential());

  const mailbox = Buffer.alloc(32, 1).toString('base64url');
  const recipient = Buffer.alloc(32, 2).toString('base64url');
  const descriptorData = {
    authorizationRevision: 1,
    mailboxId: mailbox,
    maxCiphertextExpiresAt: 30,
    recipientPublicKey: recipient,
    validFrom: 10,
    version: 1,
    writeValidUntil: 20,
  };
  const descriptor = PrivateDeliveryDescriptor.from(descriptorData);
  assert.equal(descriptor.version, 1);
  assert.equal(descriptor.maxCiphertextExpiresAt, 30);
  assert.deepEqual(descriptor.toJSON(), descriptorData);
  for (const invalid of [
    null,
    { ...descriptorData, extra: true },
    { ...descriptorData, version: 2 },
    { ...descriptorData, authorizationRevision: -1 },
    { ...descriptorData, mailboxId: 'invalid' },
    { ...descriptorData, recipientPublicKey: 'invalid' },
    { ...descriptorData, validFrom: -1 },
    { ...descriptorData, writeValidUntil: 10 },
    { ...descriptorData, maxCiphertextExpiresAt: 19 },
  ]) {
    expectInvalid(() => PrivateDeliveryDescriptor.from(invalid));
  }

  for (const invalid of [new Uint8Array(), new Uint8Array(1024 * 1024 + 1)]) {
    expectInvalid(() => PrivateDeliveryFrame.application(invalid));
  }
  for (const invalid of [
    null,
    'x'.repeat(1400001),
    '[]',
    '{"kind":"mls-application","mlsMessage":"AQ==","version":1,"x":1}',
    '{ "kind":"mls-application","mlsMessage":"AQ==","version":1}',
    '{"kind":"mls-application","mlsMessage":1,"version":1}',
    '{"kind":"mls-application","mlsMessage":"","version":1}',
    '{"kind":"mls-application","mlsMessage":"AB","version":1}',
  ]) {
    expectInvalid(() => PrivateDeliveryFrame.fromCanonicalJson(invalid));
  }

  for (const invalid of [
    null,
    { ...descriptorData, bucketBytes: 4096, ciphertext: '', deliveryId: Buffer.alloc(16).toString('base64url'), expiresAt: 20 },
  ]) {
    await expectInvalidAsync(() => PrivateDeliveryEnvelope.open(invalid, new Uint8Array(), 10));
  }
  const header = {
    bucketBytes: 4096,
    deliveryId: Buffer.alloc(16).toString('base64url'),
    expiresAt: 20,
    mailboxId: mailbox,
    version: 1,
  };
  for (const invalid of [
    { ...header, extra: true },
    { ...header, version: 2 },
    { ...header, expiresAt: -1 },
    { ...header, bucketBytes: 8192 },
    { ...header, mailboxId: 'invalid' },
    { ...header, deliveryId: 'invalid' },
  ]) {
    expectInvalid(() => PrivateDeliveryEnvelope.headerAad(invalid));
  }
  const invalidOpenEnvelope = { ...header, ciphertext: Buffer.alloc(4096).toString('base64') };
  await expectInvalidAsync(() => PrivateDeliveryEnvelope.open(invalidOpenEnvelope, new Uint8Array(32), 21));
  await expectInvalidAsync(() => PrivateDeliveryEnvelope.open(invalidOpenEnvelope, new Uint8Array(), 10));
  await expectInvalidAsync(() =>
    PrivateDeliveryEnvelope.open(
      { ...header, ciphertext: '='.repeat(Math.ceil(4096 / 3) * 4) },
      new Uint8Array(32),
      10,
    ),
  );
  const nonCanonicalCiphertext = Buffer.alloc(4096, 251).toString('base64').replace('+', '-');
  await expectInvalidAsync(() =>
    PrivateDeliveryEnvelope.open(
      { ...header, ciphertext: nonCanonicalCiphertext },
      new Uint8Array(32),
      10,
    ),
  );
  expectInvalid(() => PrivateDeliveryEnvelope.framePlaintext(PrivateDeliveryFrame.application(bytes('x')), 8192));
  expectInvalid(() =>
    PrivateDeliveryEnvelope.framePlaintext(
      PrivateDeliveryFrame.application(new Uint8Array(5000)),
      4096,
    ),
  );
  await expectInvalidAsync(() =>
    PrivateDeliveryEnvelope.seal(
      PrivateDeliveryFrame.application(bytes('x')),
      descriptor,
      0,
      1,
      4096,
    ),
  );

  await expectInvalidAsync(() => PrivateDeliveryKeySchedule.generate(-1, 1, 1));
  await expectInvalidAsync(() => PrivateDeliveryKeySchedule.generate(1, -1, 1));
  await expectInvalidAsync(() => PrivateDeliveryKeySchedule.generate(1, 1, 31 * 24 * 60 * 60 * 1000));
  let schedule = await PrivateDeliveryKeySchedule.generate(10, 1, 1000);
  expectInvalid(() => schedule.descriptorFor(9 * 24 * 60 * 60 * 1000));
  expectInvalid(() => schedule.revoke(['missing']));
  const firstMailbox = schedule.descriptors[0].mailboxId;
  expectInvalid(() => schedule.revoke([firstMailbox, firstMailbox]));
  const protectedSchedule = schedule.protect(root);
  assert.equal(typeof protectedSchedule.valueOf(), 'string');
  schedule.destroy();

  const openSchedule = await PrivateDeliveryKeySchedule.generate(10, 1, 1000);
  const openDescriptor = openSchedule.descriptors[0];
  const maliciousHeader = {
    bucketBytes: 4096,
    deliveryId: Buffer.alloc(16, 7).toString('base64url'),
    expiresAt: openDescriptor.writeValidUntil,
    mailboxId: openDescriptor.mailboxId,
    version: 1,
  };
  const sealMalformedPlaintext = async (plaintext) => {
    const suite = await getMlsCiphersuite();
    const publicKey = await suite.hpke.importPublicKey(
      Buffer.from(openDescriptor.recipientPublicKey, 'base64url'),
    );
    const encrypted = await suite.hpke.seal(
      publicKey,
      plaintext,
      bytes('pigeon.private-delivery.v1\0'),
      bytes(PrivateDeliveryEnvelope.headerAad(maliciousHeader)),
    );
    return {
      ...maliciousHeader,
      ciphertext: Buffer.concat([
        Buffer.from(encrypted.enc),
        Buffer.from(encrypted.ct),
      ]).toString('base64'),
    };
  };
  const emptyLengthEnvelope = await sealMalformedPlaintext(
    new Uint8Array(4096 - 48),
  );
  await expectInvalidAsync(() => openSchedule.open(emptyLengthEnvelope, 10));
  const padded = PrivateDeliveryEnvelope.framePlaintext(
    PrivateDeliveryFrame.application(bytes('x')),
    4096,
  );
  padded[padded.length - 1] = 1;
  const nonZeroPaddingEnvelope = await sealMalformedPlaintext(padded);
  await expectInvalidAsync(() =>
    openSchedule.open(nonZeroPaddingEnvelope, 10),
  );
  openSchedule.destroy();
  expectInvalid(() => schedule.descriptors);
  expectInvalid(() => schedule.commitment);
  expectInvalid(() => schedule.protect(root));
  schedule.destroy();

  const invalidScheduleState = RootProtectedEnvelope.protect(
    bytes('{"entries":[],"version":2}'),
    root,
    'pigeon.private-delivery-key-schedule.v1',
    32768,
  );
  await expectInvalidAsync(() =>
    PrivateDeliveryKeySchedule.restore(
      new ProtectedPrivateDeliveryKeySchedule(invalidScheduleState),
      root,
      DeliveryBase64Url.encode(new Uint8Array(32)),
    ),
  );
  const validScheduleState = JSON.parse(
    Buffer.from(protectedSchedule.unlock(root)).toString('utf8'),
  );
  const nonCanonicalScheduleState = RootProtectedEnvelope.protect(
    bytes(JSON.stringify({ version: 1, entries: [] })),
    root,
    'pigeon.private-delivery-key-schedule.v1',
    32768,
  );
  await expectInvalidAsync(() =>
    PrivateDeliveryKeySchedule.restore(
      new ProtectedPrivateDeliveryKeySchedule(nonCanonicalScheduleState),
      root,
      DeliveryBase64Url.encode(new Uint8Array(32)),
    ),
  );
  const partiallyRestoredScheduleState = RootProtectedEnvelope.protect(
    bytes(canonicalize({
      entries: [
        validScheduleState.entries[0],
        { ...validScheduleState.entries[1], privateKey: 'AA==' },
      ],
      version: 1,
    })),
    root,
    'pigeon.private-delivery-key-schedule.v1',
    32768,
  );
  await expectInvalidAsync(() =>
    PrivateDeliveryKeySchedule.restore(
      new ProtectedPrivateDeliveryKeySchedule(partiallyRestoredScheduleState),
      root,
      DeliveryBase64Url.encode(new Uint8Array(32)),
    ),
  );
  const invalidScheduleDomain = 'pigeon.private-delivery-key-schedule.v1';
  for (const state of [
    canonicalize({ entries: Array.from({ length: 9 }, () => null), version: 1 }),
    canonicalize({ entries: [null], version: 1 }),
    canonicalize({ entries: [{ descriptor: descriptorData, privateKey: 'AA==' }], version: 1 }),
    canonicalize({ entries: [{ descriptor: descriptorData, privateKey: Buffer.alloc(32).toString('base64') }], version: 1 }),
  ]) {
    const serialized = RootProtectedEnvelope.protect(
      bytes(state),
      root,
      invalidScheduleDomain,
      32768,
    );
    await expectInvalidAsync(() =>
      PrivateDeliveryKeySchedule.restore(
        new ProtectedPrivateDeliveryKeySchedule(serialized),
        root,
        DeliveryBase64Url.encode(new Uint8Array(32)),
      ),
    );
  }

  await expectInvalidAsync(() =>
    AuthenticatedPrivateDeliverySchedule.sign([], founderIdentity.credential, new Uint8Array(48)),
  );
  const signedSchedule = await PrivateDeliveryKeySchedule.generate(10, 1, 1000);
  const signedDescriptors = signedSchedule.descriptors;
  await expectInvalidAsync(() =>
    founderIdentity.authenticateDeliverySchedule([
      signedDescriptors[0],
      signedDescriptors[0],
    ]),
  );
  const descriptorWith = (descriptorValue, overrides) =>
    PrivateDeliveryDescriptor.from({ ...descriptorValue.toJSON(), ...overrides });
  await expectInvalidAsync(() =>
    founderIdentity.authenticateDeliverySchedule([
      descriptorWith(signedDescriptors[0], {
        writeValidUntil: signedDescriptors[0].writeValidUntil - 1,
      }),
    ]),
  );
  await expectInvalidAsync(() =>
    founderIdentity.authenticateDeliverySchedule([
      signedDescriptors[0],
      descriptorWith(signedDescriptors[1], {
        maxCiphertextExpiresAt: signedDescriptors[1].maxCiphertextExpiresAt + 1,
      }),
    ]),
  );
  await expectInvalidAsync(() =>
    founderIdentity.authenticateDeliverySchedule([
      signedDescriptors[0],
      descriptorWith(signedDescriptors[1], {
        validFrom: signedDescriptors[1].validFrom + 1,
        writeValidUntil: signedDescriptors[1].writeValidUntil + 1,
        maxCiphertextExpiresAt: signedDescriptors[1].maxCiphertextExpiresAt + 1,
      }),
    ]),
  );
  const authenticatedSchedule = await founderIdentity.authenticateDeliverySchedule(signedDescriptors);
  const emptyAuthenticatedSchedule = canonicalize({
    ...JSON.parse(authenticatedSchedule.valueOf()),
    descriptors: [],
  });
  await expectInvalidAsync(() =>
    AuthenticatedPrivateDeliverySchedule.verify(
      emptyAuthenticatedSchedule,
      founderIdentity.credential,
      1,
    ),
  );
  const authenticatedDocument = JSON.parse(authenticatedSchedule.valueOf());
  await expectInvalidAsync(() =>
    AuthenticatedPrivateDeliverySchedule.verify(
      null,
      founderIdentity.credential,
      1,
    ),
  );
  await expectInvalidAsync(() =>
    AuthenticatedPrivateDeliverySchedule.verify(
      JSON.stringify({
        version: authenticatedDocument.version,
        descriptors: authenticatedDocument.descriptors,
        signature: authenticatedDocument.signature,
        signerIdentity: authenticatedDocument.signerIdentity,
        signerPublicKey: authenticatedDocument.signerPublicKey,
      }),
      founderIdentity.credential,
      1,
    ),
  );
  await expectInvalidAsync(() =>
    AuthenticatedPrivateDeliverySchedule.verify(
      canonicalize({ ...authenticatedDocument, signature: null }),
      founderIdentity.credential,
      1,
    ),
  );
  await expectInvalidAsync(() =>
    AuthenticatedPrivateDeliverySchedule.verify(
      canonicalize({ ...authenticatedDocument, signature: 'AA' }),
      founderIdentity.credential,
      1,
    ),
  );
  await expectInvalidAsync(() =>
    AuthenticatedPrivateDeliverySchedule.verify(
      authenticatedSchedule.valueOf(),
      founderIdentity.credential,
      2,
    ),
  );
  await expectInvalidAsync(() =>
    AuthenticatedPrivateDeliverySchedule.verify(
      'x'.repeat(32769),
      founderIdentity.credential,
      1,
    ),
  );
  signedSchedule.destroy();

  assert.equal(
    await validateMlsCredential(
      { credentialType: 'x509', identity: bytes('ignored') },
      new Uint8Array(32),
      trusted,
    ),
    false,
  );
  assert.equal(
    await validateMlsCredential(
      { credentialType: 'basic', identity: bytes('accepted') },
      new Uint8Array(32),
      trusted,
    ),
    true,
  );
  assert.equal(
    acceptsMlsMemberCount(128, { kind: 'proposal', proposal: {} }, 128),
    true,
  );
  assert.equal(
    acceptsMlsMemberCount(
      127,
      { kind: 'commit', proposals: [], senderLeafIndex: undefined },
      128,
    ),
    true,
  );
  assert.equal(
    acceptsMlsMemberCount(
      128,
      { kind: 'commit', proposals: [], senderLeafIndex: 0 },
      128,
    ),
    true,
  );
  expectInvalid(() => requireMlsWelcome(undefined));
  const welcomeValue = {};
  assert.equal(requireMlsWelcome(welcomeValue), welcomeValue);
  await expectInvalidAsync(() =>
    AuthenticatedPrivateDeliverySchedule.verify('{}', founderIdentity.credential, 1),
  );

  for (const Protected of [
    ProtectedMlsDeviceIdentity,
    ProtectedMlsGroupState,
    ProtectedMlsJoinPackage,
    ProtectedPrivateDeliveryKeySchedule,
  ]) {
    expectInvalid(() => new Protected('invalid'));
  }

  console.log('PASS MLS and private-delivery validation boundaries.');
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
