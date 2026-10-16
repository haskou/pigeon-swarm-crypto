const assert = require('node:assert/strict');
const mls = require('../../dist/mls/index.cjs');
const { KeyPair } = require('../../dist/index.js');
const {
  buildMlsCommit,
} = require('../../dist/mls/internal/MlsCommitBuilder.js');
const rules = require('../../dist/mls/internal/MlsGroupRules.js');
const {
  getMlsCiphersuite,
} = require('../../dist/mls/internal/MlsRuntime.js');
const { runInChromium } = require('./chromium-modules.cjs');

const groupError = {
  message: 'Invalid MLS group operation',
  name: 'InvalidMlsGroupError',
};
const credentialError = {
  message: 'Invalid MLS credential',
  name: 'InvalidMlsCredentialError',
};
const policy = {
  admits: () => true,
  allows: () => true,
  frontier: () => [],
  priority: () => 0,
  reach: () => 0,
  withheld: () => false,
};

const keyOf = async () => {
  const identity = await KeyPair.generate();
  const device = await KeyPair.generate();
  const owner = {
    deviceCredential: device.toPrimitives().publicKey,
    identityId: identity.toPrimitives().publicKey.split('\n')[1],
  };

  return mls.MlsKeyPackage.generate(
    new mls.MlsLeafSigner(owner, identity, device),
  );
};

/** Rule helpers whose failures the group's own checks always pre-empt. */
const checkRuleGuards = () => {
  const x509 = { certificates: [], credentialType: 'x509' };

  assert.throws(() => rules.defined(undefined), groupError);
  assert.throws(() => rules.leafAt([], 0), groupError);
  assert.throws(() => rules.ownerOf(x509), credentialError);
  assert.throws(
    () => rules.verifiedOwner(x509, new Uint8Array(32)),
    credentialError,
  );
};

/**
 * The builder refuses ReInit itself, and a commit that both adds and needs
 * an UpdatePath hands the joiner its path secret in the welcome; MlsGroup
 * itself never adds in such a commit.
 */
const checkBuilder = async (tsMls) => {
  const aliceKey = await keyOf();
  const keys = [await keyOf(), await keyOf()];
  const alice = await mls.MlsGroup.create('community-1', aliceKey, policy);
  await alice.add(keys.map((key) => key.publicBytes));
  alice.confirm('c-0001');
  const daveKey = await keyOf();
  const { keyPackage } = tsMls.decodeMlsMessage(daveKey.publicBytes, 0)[0];
  const binding = mls.MlsRosterFrontier.encode([]);
  const state = {
    ...tsMls.decodeGroupState(alice.serialize(), 0)[0],
    clientConfig: rules.clientConfig,
  };
  const cs = await getMlsCiphersuite();
  const build = (proposals) =>
    buildMlsCommit(
      state,
      proposals,
      binding,
      [
        {
          extensionData: binding,
          extensionType: mls.MlsRosterFrontier.EXTENSION_TYPE,
        },
      ],
      cs,
    );

  await assert.rejects(
    build([
      {
        proposalType: 'reinit',
        reinit: {
          cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
          extensions: [],
          groupId: new TextEncoder().encode('community-2'),
          version: 'mls10',
        },
      },
    ]),
    groupError,
  );
  const { welcome } = await build([
    { add: { keyPackage }, proposalType: 'add' },
    { proposalType: 'remove', remove: { removed: 1 } },
  ]);
  const dave = await mls.MlsGroup.join(
    'community-1',
    daveKey,
    tsMls.encodeMlsMessage({
      version: 'mls10',
      welcome,
      wireformat: 'mls_welcome',
    }),
    policy,
  );

  assert.equal(dave.epoch, alice.epoch + 1n);
  assert.deepEqual(
    [...dave.identities()].sort(),
    [aliceKey, keys[1], daveKey].map((key) => key.owner.identityId).sort(),
  );
};

(async () => {
  const { run } = await import('./mls-group-scenarios.mjs');
  const tsMls = await import('ts-mls');
  const ran = await run({ KeyPair, mls, tsMls });

  console.log(`PASS ${ran.length} MlsGroup scenarios in Node.`);
  assert.deepEqual(await runInChromium('mls-group-scenarios.mjs'), ran);
  console.log(`PASS ${ran.length} MlsGroup scenarios in Chromium.`);
  checkRuleGuards();
  await checkBuilder(tsMls);
  console.log('PASS MlsGroup rule guards and commit builder in Node.');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
