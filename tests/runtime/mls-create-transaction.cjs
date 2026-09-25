const assert = require('node:assert/strict');

const { UserRootKey } = require('../../dist');
const {
  MlsGroupSession,
} = require('../../dist/mls/MlsGroupSession.js');
const { MlsJoinPackage } = require('../../dist/mls/MlsJoinPackage.js');
const {
  getMlsCiphersuite,
} = require('../../dist/mls/internal/MlsRuntime.js');

const bytes = (value) => new TextEncoder().encode(value);

const run = async () => {
  const mls = await import('ts-mls');
  const suite = await getMlsCiphersuite();
  const signingKey = await suite.signature.keygen();
  const generated = await mls.generateKeyPackageWithKey(
    { credentialType: 'basic', identity: bytes('failed-founder') },
    mls.defaultCapabilities(),
    mls.defaultLifetime,
    [],
    signingKey,
    suite,
  );
  const joinPackage = MlsJoinPackage.fromGenerated(
    generated.publicPackage,
    generated.privatePackage,
  );
  const originalRandomBytes = suite.rng.randomBytes;
  suite.rng.randomBytes = () => {
    throw new Error('random source failed');
  };
  try {
    await assert.rejects(() =>
      MlsGroupSession.create(bytes('failed-group'), joinPackage, async () => true),
    );
  } finally {
    suite.rng.randomBytes = originalRandomBytes;
  }
  assert.equal(
    typeof joinPackage.protect(UserRootKey.generate()).valueOf(),
    'string',
  );

  console.log('PASS failed MLS group creation preserves the founder package.');
};

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
