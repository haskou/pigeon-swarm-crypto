const assert = require('node:assert/strict');
const mls = require('../../dist/mls/index.cjs');
const { KeyPair } = require('../../dist/index.js');
const frontier = require('../../vectors/mls-roster-frontier.json');
const leaf = require('../../vectors/mls-leaf-credential.json');
const roster = require('../../vectors/group-mailbox-roster-extension.json');
const { runInChromium } = require('./chromium-modules.cjs');

(async () => {
  const vectors = { frontier, leaf, roster };
  const { run } = await import('./mls-group-codecs-cases.mjs');
  const checked = run({ KeyPair, mls }, vectors);

  console.log(`PASS ${checked} MLS codec vectors in Node.`);
  assert.equal(await runInChromium('mls-group-codecs-cases.mjs', vectors), checked);
  console.log(`PASS ${checked} MLS codec vectors in Chromium.`);
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
