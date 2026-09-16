import {
  createApplicationMessage,
  createCommit,
  createGroup,
  joinGroup,
  processMessage,
  getCiphersuiteImpl,
  getCiphersuiteFromName,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  generateKeyPackage,
  generateKeyPackageWithKey,
  encodeGroupState,
  decodeGroupState,
  encodeMlsMessage,
  decodeMlsMessage,
  zeroOutUint8Array,
} from 'ts-mls';
import { defaultClientConfig } from 'ts-mls/clientConfig.js';

const text = new TextEncoder();
const read = new TextDecoder();
const equal = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const check = (ok, message) => {
  if (!ok) throw new Error(message);
};

export async function runLifecycle() {
  const cs = await getCiphersuiteImpl(
    getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'),
  );
  const packages = await Promise.all(
    ['alice', 'bob', 'carol'].map((name) =>
      generateKeyPackage(
        { credentialType: 'basic', identity: text.encode(name) },
        defaultCapabilities(),
        defaultLifetime,
        [],
        cs,
      ),
    ),
  );
  const pinned = new Map(
    packages.map((p) => [
      read.decode(p.publicPackage.leafNode.credential.identity),
      p.publicPackage.leafNode.signaturePublicKey,
    ]),
  );
  const config = {
    ...defaultClientConfig,
    authService: {
      async validateCredential(credential, key) {
        const trusted = pinned.get(read.decode(credential.identity));
        return trusted !== undefined && equal(trusted, key);
      },
    },
  };
  const duplicate = await generateKeyPackageWithKey(
    packages[0].publicPackage.leafNode.credential,
    defaultCapabilities(),
    defaultLifetime,
    [],
    {
      signKey: packages[0].privatePackage.signaturePrivateKey,
      publicKey: packages[0].publicPackage.leafNode.signaturePublicKey,
    },
    cs,
  );
  check(
    equal(
      duplicate.publicPackage.leafNode.signaturePublicKey,
      packages[0].publicPackage.leafNode.signaturePublicKey,
    ),
    'Signing identity unexpectedly changed',
  );
  check(
    !equal(
      duplicate.publicPackage.leafNode.hpkePublicKey,
      packages[0].publicPackage.leafNode.hpkePublicKey,
    ),
    'HPKE leaf key reused with signing key',
  );
  check(
    !equal(duplicate.publicPackage.initKey, packages[0].publicPackage.initKey),
    'HPKE init key reused with signing key',
  );
  const wire = (message) => {
    const bytes = encodeMlsMessage(message);
    const decoded = decodeMlsMessage(bytes, 0);
    check(
      decoded && decoded[1] === bytes.length,
      'Incomplete MLS wire decoding',
    );
    return decoded[0];
  };
  const restore = (bytes) => {
    const decoded = decodeGroupState(bytes, 0);
    check(
      decoded && decoded[1] === bytes.length,
      'Incomplete state reconstruction',
    );
    return { ...decoded[0], clientConfig: config };
  };
  const adopt = (result) => {
    result.consumed.forEach(zeroOutUint8Array);
    return result.newState;
  };
  const receive = (state, message) =>
    processMessage(wire(message), state, emptyPskIndex, () => 'accept', cs);
  const rejects = async (operation, label) => {
    let rejected = false;
    try {
      await operation();
    } catch {
      rejected = true;
    }
    check(rejected, label);
  };
  let alice = await createGroup(
    text.encode('isolated-rotation-evaluation'),
    packages[0].publicPackage,
    packages[0].privatePackage,
    [],
    cs,
    config,
  );
  const added = await createCommit(
    { state: alice, cipherSuite: cs },
    {
      extraProposals: packages
        .slice(1)
        .map((p) => ({
          proposalType: 'add',
          add: { keyPackage: p.publicPackage },
        })),
    },
  );
  alice = adopt(added);
  let [bob, carol] = await Promise.all(
    packages
      .slice(1)
      .map((p) =>
        joinGroup(
          added.welcome,
          p.publicPackage,
          p.privatePackage,
          emptyPskIndex,
          cs,
          alice.ratchetTree,
          undefined,
          config,
        ),
      ),
  );
  const beforeMessage = await createApplicationMessage(
    alice,
    text.encode('before removal'),
    cs,
  );
  alice = adopt(beforeMessage);
  const applicationWire = (result) => ({
    privateMessage: result.privateMessage,
    wireformat: 'mls_private_message',
    version: 'mls10',
  });
  for (const state of [bob, carol]) {
    const received = await receive(state, applicationWire(beforeMessage));
    check(
      received.kind === 'applicationMessage' &&
        read.decode(received.message) === 'before removal',
      'Initial plaintext mismatch',
    );
    if (state === bob) bob = adopt(received);
    else carol = adopt(received);
  }
  const impostor = await generateKeyPackage(
    { credentialType: 'basic', identity: text.encode('mallory') },
    defaultCapabilities(),
    defaultLifetime,
    [],
    cs,
  );
  await rejects(
    () =>
      createCommit(
        { state: restore(encodeGroupState(alice)), cipherSuite: cs },
        {
          extraProposals: [
            {
              proposalType: 'add',
              add: { keyPackage: impostor.publicPackage },
            },
          ],
        },
      ),
    'An unpinned credential joined the group',
  );
  const stolenBob = encodeGroupState(bob);
  const offlineCarol = encodeGroupState(carol);
  const removed = await createCommit(
    { state: alice, cipherSuite: cs },
    { extraProposals: [{ proposalType: 'remove', remove: { removed: 1 } }] },
  );
  alice = adopt(removed);
  check(alice.groupContext.epoch === 2n, 'Removal must advance the epoch');
  const bobObservedRemoval = await receive(restore(stolenBob), removed.commit);
  check(
    bobObservedRemoval.newState.groupActiveState.kind === 'removedFromGroup',
    'The targeted device was not actually removed',
  );
  const dishonestBob = bobObservedRemoval.newState;
  dishonestBob.groupActiveState = { kind: 'active' };
  dishonestBob.groupContext = structuredClone(alice.groupContext);
  dishonestBob.ratchetTree = structuredClone(alice.ratchetTree);
  const afterMessage = await createApplicationMessage(
    alice,
    text.encode('after removal'),
    cs,
  );
  alice = adopt(afterMessage);
  await rejects(
    () => receive(restore(stolenBob), applicationWire(afterMessage)),
    'Removed device read the new epoch',
  );
  await rejects(
    () => receive(dishonestBob, applicationWire(afterMessage)),
    'Ignoring removal and applying public state restored decryption',
  );
  const forgedBob = restore(stolenBob);
  forgedBob.groupContext = structuredClone(alice.groupContext);
  await rejects(
    () => receive(forgedBob, applicationWire(afterMessage)),
    'Public epoch/context substitution restored access',
  );
  carol = adopt(await receive(restore(offlineCarol), removed.commit));
  carol = restore(encodeGroupState(carol));
  const tampered = structuredClone(applicationWire(afterMessage));
  tampered.privateMessage.ciphertext[0] ^= 1;
  await rejects(
    () => receive(restore(encodeGroupState(carol)), tampered),
    'Modified ciphertext accepted',
  );
  const delivered = await receive(carol, applicationWire(afterMessage));
  check(
    delivered.kind === 'applicationMessage' &&
      read.decode(delivered.message) === 'after removal',
    'Offline retained member failed to recover',
  );
  carol = adopt(delivered);
  await rejects(
    () => receive(carol, applicationWire(afterMessage)),
    'Duplicate application message accepted',
  );
  await rejects(
    () => receive(carol, removed.commit),
    'Old commit accepted twice',
  );
  const refreshed = await createCommit({ state: alice, cipherSuite: cs });
  alice = adopt(refreshed);
  carol = adopt(await receive(carol, refreshed.commit));
  check(
    alice.groupContext.epoch === 3n && carol.groupContext.epoch === 3n,
    'Refresh without membership change did not advance',
  );
  const finalMessage = await createApplicationMessage(
    alice,
    text.encode('after refresh'),
    cs,
  );
  alice = adopt(finalMessage);
  const finalReceived = await receive(
    restore(encodeGroupState(carol)),
    applicationWire(finalMessage),
  );
  check(
    finalReceived.kind === 'applicationMessage' &&
      read.decode(finalReceived.message) === 'after refresh',
    'Final plaintext mismatch',
  );
  adopt(finalReceived);
  await rejects(
    () => receive(restore(stolenBob), applicationWire(finalMessage)),
    'Removed device recovered access after another rotation',
  );
  return {
    suite: cs.name,
    participants: 3,
    finalEpoch: String(alice.groupContext.epoch),
    independentEncryptionKeys: true,
    retainedRemovedStateRejected: true,
    offlineCatchupAndReload: true,
    replayRejected: true,
  };
}
