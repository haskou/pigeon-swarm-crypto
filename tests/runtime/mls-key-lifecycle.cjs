const assert = require('node:assert/strict');

const {
  MlsApplicationFrame,
  MlsCommitFrame,
  MlsDeviceIdentity,
  MlsGroupSession,
  MlsJoinPackage,
  PrivateDeliveryEnvelope,
  PrivateDeliveryFrame,
} = require('../../dist/mls/index.cjs');
const { UserRootKey } = require('../../dist');

const text = new TextEncoder();
const read = new TextDecoder();
const key = (bytes) => Buffer.from(bytes).toString('base64url');

const run = async () => {
  let aliceIdentity = await MlsDeviceIdentity.generate(text.encode('alice'));
  const bobIdentity = await MlsDeviceIdentity.generate(text.encode('bob'));
  const carolIdentity = await MlsDeviceIdentity.generate(text.encode('carol'));
  const identityRoot = UserRootKey.generate();
  const protectedAliceIdentity = aliceIdentity.protect(identityRoot);
  assert.equal(JSON.stringify(aliceIdentity), '{}');
  const originalAliceIdentity = aliceIdentity;
  aliceIdentity = await MlsDeviceIdentity.restore(
    protectedAliceIdentity,
    identityRoot,
  );
  originalAliceIdentity.destroy();
  await assert.rejects(() => originalAliceIdentity.createJoinPackage());
  await assert.rejects(() =>
    MlsDeviceIdentity.restore(
      protectedAliceIdentity,
      UserRootKey.generate(),
    ),
  );
  const bobRoot = UserRootKey.generate();
  const carolRoot = UserRootKey.generate();
  const trusted = new Map(
    [aliceIdentity, bobIdentity, carolIdentity].map((identity) => [
      key(identity.credential.identity),
      key(identity.credential.signaturePublicKey),
    ]),
  );
  const verifyCredential = async ({ identity, signaturePublicKey }) =>
    trusted.get(key(identity)) === key(signaturePublicKey);
  const alicePackage = await aliceIdentity.createJoinPackage();
  assert.equal(JSON.stringify(alicePackage), '{}');
  let bobPackage = await bobIdentity.createJoinPackage();
  const carolPackage = await carolIdentity.createJoinPackage();
  const joinRoot = UserRootKey.generate();
  const protectedBobPackage = bobPackage.protect(joinRoot);
  const originalBobPackage = bobPackage;
  bobPackage = await MlsJoinPackage.restore(protectedBobPackage, joinRoot);
  originalBobPackage.destroy();
  await assert.rejects(() =>
    MlsJoinPackage.restore(protectedBobPackage, UserRootKey.generate()),
  );

  assert.notDeepEqual(
    alicePackage.initPublicKey,
    aliceIdentity.credential.signaturePublicKey,
  );
  assert.notDeepEqual(
    alicePackage.leafPublicKey,
    aliceIdentity.credential.signaturePublicKey,
  );
  assert.notDeepEqual(alicePackage.initPublicKey, alicePackage.leafPublicKey);

  let alice = await MlsGroupSession.create(
    text.encode('private-community'),
    alicePackage,
    verifyCredential,
  );
  assert.equal(JSON.stringify(alice), '{}');
  await assert.rejects(() =>
    alice.addMembers(Array.from({ length: 128 }, () => bobPackage.publicBytes)),
  );
  await assert.rejects(() =>
    MlsGroupSession.create(
      text.encode('reused-founder-package'),
      alicePackage,
      verifyCredential,
    ),
  );
  const added = await alice.addMembers([
    bobPackage.publicBytes,
    carolPackage.publicBytes,
  ]);
  alice = added.session;
  let bob = await MlsGroupSession.join(
    added.welcome,
    bobPackage,
    verifyCredential,
  );
  await assert.rejects(() =>
    MlsGroupSession.join(added.welcome, bobPackage, verifyCredential),
  );
  let carol = await MlsGroupSession.join(
    added.welcome,
    carolPackage,
    verifyCredential,
  );
  assert.equal(alice.epoch, 1n);
  const preRemovalContextHash = alice.contextHash;
  assert.equal(preRemovalContextHash.length, 43);

  const beforeRemoval = await alice.encrypt(text.encode('before removal'));
  alice = beforeRemoval.session;
  const bobPreMessageState = bob.protectState(bobRoot);
  const bobPreMessageCommitment = bob.stateCommitment;
  await assert.rejects(() =>
    bob.applyCommit(MlsCommitFrame.create(beforeRemoval.frame.payloadBytes())),
  );
  const bobBefore = await bob.decrypt(beforeRemoval.frame);
  bob = bobBefore.session;
  assert.equal(read.decode(bobBefore.plaintext), 'before removal');
  assert.notEqual(bob.stateCommitment, bobPreMessageCommitment);
  assert.throws(() =>
    MlsGroupSession.restore(
      bobPreMessageState,
      bobRoot,
      verifyCredential,
      1n,
      bob.stateCommitment,
    ),
  );
  const carolBefore = await carol.decrypt(beforeRemoval.frame);
  carol = carolBefore.session;
  assert.equal(read.decode(carolBefore.plaintext), 'before removal');

  const stolenBobState = bob.protectState(bobRoot);
  const stolenBobCommitment = bob.stateCommitment;
  const offlineCarolState = carol.protectState(carolRoot);
  const offlineCarolCommitment = carol.stateCommitment;
  assert.equal(stolenBobState.valueOf().includes('before removal'), false);
  assert.throws(() =>
    MlsGroupSession.restore(
      stolenBobState,
      UserRootKey.generate(),
      verifyCredential,
      1n,
      stolenBobCommitment,
    ),
  );
  const removed = await alice.removeMembers([bobIdentity.credential.identity]);
  alice = removed.session;
  assert.notEqual(alice.contextHash, preRemovalContextHash);
  const postRemovalState = alice.protectState(identityRoot);
  const postRemovalCommitment = alice.stateCommitment;
  assert.throws(() =>
    MlsGroupSession.restore(
      postRemovalState,
      identityRoot,
      verifyCredential,
      1n,
      postRemovalCommitment,
    ),
  );
  assert.throws(() =>
    MlsGroupSession.restore(
      offlineCarolState,
      carolRoot,
      verifyCredential,
      2n,
      offlineCarolCommitment,
    ),
  );
  const removedBob = await bob.applyCommit(removed.commit);
  assert.equal(removedBob.active, false);
  carol = await MlsGroupSession.restore(
    offlineCarolState,
    carolRoot,
    verifyCredential,
    1n,
    offlineCarolCommitment,
  );
  carol = await carol.applyCommit(removed.commit);

  const afterRemoval = await alice.encrypt(text.encode('after removal'));
  alice = afterRemoval.session;
  const tamperedBytes = afterRemoval.frame.toBytes();
  tamperedBytes[tamperedBytes.length - 1] ^= 1;
  await assert.rejects(
    () => carol.decrypt(MlsApplicationFrame.fromBytes(tamperedBytes)),
    (error) => error.message === 'Invalid MLS frame',
  );
  const carolAfter = await carol.decrypt(afterRemoval.frame);
  carol = carolAfter.session;
  assert.equal(read.decode(carolAfter.plaintext), 'after removal');
  const stolenBob = await MlsGroupSession.restore(
    stolenBobState,
    bobRoot,
    verifyCredential,
    1n,
    stolenBobCommitment,
  );
  await assert.rejects(() => stolenBob.decrypt(afterRemoval.frame));
  await assert.rejects(() => carol.decrypt(afterRemoval.frame));

  const refreshed = await alice.refresh();
  alice = refreshed.session;
  const outOfOrderCarol = MlsGroupSession.restore(
    offlineCarolState,
    carolRoot,
    verifyCredential,
    1n,
    offlineCarolCommitment,
  );
  await assert.rejects(
    () => outOfOrderCarol.applyCommit(refreshed.commit),
    (error) => error.message === 'Invalid MLS frame',
  );
  carol = await carol.applyCommit(refreshed.commit);
  await assert.rejects(
    () => carol.applyCommit(refreshed.commit),
    (error) => error.message === 'Invalid MLS frame',
  );
  assert.equal(alice.epoch, 3n);
  const currentCarolState = carol.protectState(carolRoot);
  const currentCarolCommitment = carol.stateCommitment;
  const restoredCarol = await MlsGroupSession.restore(
    currentCarolState,
    carolRoot,
    verifyCredential,
    3n,
    currentCarolCommitment,
  );
  const afterRefresh = await alice.encrypt(text.encode('after refresh'));
  alice = afterRefresh.session;
  const final = await restoredCarol.decrypt(afterRefresh.frame);
  assert.equal(read.decode(final.plaintext), 'after refresh');
  await assert.rejects(() => stolenBob.decrypt(afterRefresh.frame));

  const mallory = await MlsDeviceIdentity.generate(text.encode('mallory'));
  const malloryPackage = await mallory.createJoinPackage();
  await assert.rejects(() => alice.addMembers([malloryPackage.publicBytes]));

  const applicationBytes = afterRefresh.frame.toBytes();
  const commitBytes = refreshed.commit.toBytes();
  assert.throws(() => MlsCommitFrame.fromBytes(applicationBytes));
  assert.throws(() => MlsApplicationFrame.fromBytes(commitBytes));
  assert.throws(() => MlsApplicationFrame.fromBytes(new Uint8Array(0)));

  const mls = await import('ts-mls');
  const capRoot = UserRootKey.generate();
  const capFounder = await MlsDeviceIdentity.generate(text.encode('cap-founder'));
  const capFounderPackage = await capFounder.createJoinPackage();
  trusted.set(
    key(capFounder.credential.identity),
    key(capFounder.credential.signaturePublicKey),
  );
  const capMembers = await Promise.all(
    Array.from({ length: 127 }, async (_, index) => {
      const identity = await MlsDeviceIdentity.generate(
        text.encode(`cap-member-${index}`),
      );
      trusted.set(
        key(identity.credential.identity),
        key(identity.credential.signaturePublicKey),
      );

      return {
        identity,
        package: await identity.createJoinPackage(),
      };
    }),
  );
  let cappedGroup = await MlsGroupSession.create(
    text.encode('member-cap'),
    capFounderPackage,
    verifyCredential,
  );
  const cappedAddition = await cappedGroup.addMembers(
    capMembers.map((member) => member.package.publicBytes),
  );
  cappedGroup = cappedAddition.session;
  const cappedObserver = await MlsGroupSession.join(
    cappedAddition.welcome,
    capMembers[0].package,
    verifyCredential,
  );
  const outsider = await MlsDeviceIdentity.generate(text.encode('cap-outsider'));
  const outsiderPackage = await outsider.createJoinPackage();
  trusted.set(
    key(outsider.credential.identity),
    key(outsider.credential.signaturePublicKey),
  );
  const protectedCappedState = cappedGroup.protectState(capRoot);
  const encodedCappedState = protectedCappedState.unlock(capRoot);
  const decodedCappedState = mls.decodeGroupState(encodedCappedState, 0);
  assert.ok(decodedCappedState);
  const rawState = decodedCappedState[0];
  rawState.clientConfig = {
    authService: { validateCredential: async () => true },
    keyPackageEqualityConfig: mls.defaultKeyPackageEqualityConfig,
    keyRetentionConfig: mls.defaultKeyRetentionConfig,
    lifetimeConfig: mls.defaultLifetimeConfig,
    paddingConfig: mls.defaultPaddingConfig,
  };
  const decodedOutsiderPackage = mls.decodeMlsMessage(
    outsiderPackage.publicBytes,
    0,
  );
  assert.equal(decodedOutsiderPackage[0].wireformat, 'mls_key_package');
  const suite = await mls.getCiphersuiteImpl(
    mls.getCiphersuiteFromName(
      'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
    ),
  );
  const overCap = await mls.createCommit(
    { cipherSuite: suite, state: rawState },
    {
      extraProposals: [
        {
          add: { keyPackage: decodedOutsiderPackage[0].keyPackage },
          proposalType: 'add',
        },
      ],
      ratchetTreeExtension: true,
    },
  );
  const overCapCommit = MlsCommitFrame.create(
    mls.encodeMlsMessage(overCap.commit),
  );
  const beforeRejectedCommitment = cappedObserver.stateCommitment;
  await assert.rejects(() => cappedObserver.applyCommit(overCapCommit));
  assert.equal(cappedObserver.stateCommitment, beforeRejectedCommitment);
  const afterRejectedCommit = await cappedGroup.encrypt(
    text.encode('after rejected over-cap commit'),
  );
  const observerAfterRejectedCommit = await cappedObserver.decrypt(
    afterRejectedCommit.frame,
  );
  assert.equal(
    read.decode(observerAfterRejectedCommit.plaintext),
    'after rejected over-cap commit',
  );
  await assert.rejects(() =>
    afterRejectedCommit.session.encrypt(new Uint8Array(128 * 1024 + 1)),
  );
  const maximumApplication = await afterRejectedCommit.session.encrypt(
    new Uint8Array(128 * 1024),
  );
  assert.equal(
    PrivateDeliveryEnvelope.framePlaintext(
      PrivateDeliveryFrame.application(maximumApplication.frame.toBytes()),
      262144,
    ).length,
    262096,
  );
  encodedCappedState.fill(0);

  console.log('PASS MLS device keys, membership changes, rotation, recovery, persistence, replay and frame separation.');
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
