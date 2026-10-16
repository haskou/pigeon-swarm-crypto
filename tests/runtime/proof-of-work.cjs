const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const { ProofOfWork } = require('../../dist');
const vectors = require('../../vectors/proof-of-work.json');

const evaluate = async (ProofOfWork, vectors) => {
  const challenges = {
    identityAdmission: ({ identityId, networkIds }) =>
      ProofOfWork.identityAdmission(identityId, networkIds),
    mailboxCreation: ({ mailboxId, postTokenHash, readTokenHash }) =>
      ProofOfWork.mailboxCreation(mailboxId, postTokenHash, readTokenHash),
  };
  const results = [];

  for (const [format, challenge] of Object.entries(challenges)) {
    for (const vector of vectors[format].accepted) {
      const proof = challenge(vector.challenge);
      results.push([
        format,
        vector.name,
        proof.verify(vector.nonce, vector.difficultyBits),
        vector.minted ? await proof.mint(vector.difficultyBits) : vector.nonce,
        vector.minted ? proof.mintSync(vector.difficultyBits) : vector.nonce,
      ]);
    }
    for (const vector of vectors[format].rejected) {
      results.push([
        format,
        vector.name,
        challenge(vector.challenge).verify(vector.nonce, vector.difficultyBits),
      ]);
    }
    for (const vector of vectors[format].invalidChallenges) {
      let message;
      try {
        challenge(vector.challenge);
      } catch (error) {
        message = error.message;
      }
      results.push([format, vector.name, message]);
    }
  }

  return results;
};

const expected = (vectors) =>
  ['identityAdmission', 'mailboxCreation'].flatMap((format) => [
    ...vectors[format].accepted.map((vector) => [
      format,
      vector.name,
      true,
      vector.nonce,
      vector.nonce,
    ]),
    ...vectors[format].rejected.map((vector) => [format, vector.name, false]),
    ...vectors[format].invalidChallenges.map((vector) => [
      format,
      vector.name,
      'Invalid proof of work',
    ]),
  ]);

(async () => {
  assert.deepEqual(await evaluate(ProofOfWork, vectors), expected(vectors));

  const bundle = await build({
    stdin: {
      contents: "export { ProofOfWork } from './dist/index.js';",
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
      '<!doctype html><title>Disposable proof of work interoperability test</title>',
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
      async ({ source, vectors }) =>
        new Function('return ' + source)()(PigeonCrypto.ProofOfWork, vectors),
      { source: evaluate.toString(), vectors },
    );
    assert.deepEqual(result, expected(vectors));
    console.log(
      'PASS Node and Chromium agree on proof of work vectors; malformed proofs and challenges are rejected.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
