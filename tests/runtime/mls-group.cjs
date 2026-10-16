const assert = require('node:assert/strict');
const mls = require('../../dist/mls/index.cjs');
const { KeyPair } = require('../../dist/index.js');
const rules = require('../../dist/mls/internal/MlsGroupRules.js');
const { runInChromium } = require('./chromium-modules.cjs');

const groupError = {
  message: 'Invalid MLS group operation',
  name: 'InvalidMlsGroupError',
};
const credentialError = {
  message: 'Invalid MLS credential',
  name: 'InvalidMlsCredentialError',
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

(async () => {
  const { run } = await import('./mls-group-scenarios.mjs');
  const tsMls = await import('ts-mls');
  const ran = await run({ KeyPair, mls, tsMls });

  console.log(`PASS ${ran.length} MlsGroup scenarios in Node.`);
  assert.deepEqual(await runInChromium('mls-group-scenarios.mjs'), ran);
  console.log(`PASS ${ran.length} MlsGroup scenarios in Chromium.`);
  checkRuleGuards();
  console.log('PASS MlsGroup rule guards in Node.');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
