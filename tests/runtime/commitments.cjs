const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const { BearerCapability, CommitmentId, StateDigest } = require('../../dist');
const bearer = require('../../vectors/bearer-capabilities.json');
const commitments = require('../../vectors/commitment-ids.json');

const owners = {
  call: ['CommitmentId', 'call'],
  community: ['CommitmentId', 'community'],
  communityChannel: ['CommitmentId', 'communityChannel'],
  communityRole: ['CommitmentId', 'communityRole'],
  communityRequest: ['CommitmentId', 'communityRequest'],
  communityModerationLog: ['CommitmentId', 'communityModerationLog'],
  mlsRecord: ['CommitmentId', 'mlsRecord'],
  privateBlobOwner: ['CommitmentId', 'privateBlobOwner'],
  oneToOneConversation: ['CommitmentId', 'oneToOneConversation'],
  groupConversation: ['CommitmentId', 'groupConversation'],
  invitation: ['CommitmentId', 'invitation'],
  stateDigest: ['StateDigest', 'of'],
  communityFrontiers: ['StateDigest', 'communityFrontiers'],
};

const evaluate = (library, bearer, commitments, owners) => {
  const attempt = (owner, method, args) => {
    try {
      return library[owner][method](...args);
    } catch (error) {
      return 'error:' + error.name + ':' + error.message;
    }
  };
  const hex = (value) =>
    Uint8Array.from(value.match(/../g) ?? [], (pair) => parseInt(pair, 16));
  const generated = library.BearerCapability.generate();

  return {
    hashes: bearer.hash.valid.map((item) =>
      attempt('BearerCapability', 'hash', [item.token]),
    ),
    rejectedTokens: bearer.hash.invalid.map((item) =>
      attempt('BearerCapability', 'hash', [item.token]),
    ),
    verified: bearer.verify.map((item) =>
      library.BearerCapability.verify(item.token, item.hash),
    ),
    generated: [
      /^[A-Za-z0-9_-]{43}$/.test(generated.token),
      library.BearerCapability.verify(generated.token, generated.hash),
    ],
    sections: Object.fromEntries(
      Object.entries(owners).map(([section, [owner, method]]) => [
        section,
        {
          valid: commitments[section].valid.map((item) =>
            attempt(owner, method, item.args),
          ),
          invalid: commitments[section].invalid.map((item) =>
            attempt(owner, method, item.args),
          ),
        },
      ]),
    ),
    bytes: commitments.bytesDigest.valid.map((item) =>
      library.StateDigest.ofBytes(hex(item.bytes)),
    ),
    groupMessages: [
      ...commitments.groupMessage.owned,
      ...commitments.groupMessage.foreign,
    ].map((item) => library.CommitmentId.isGroupMessageOf(...item.args)),
    created: [commitments.groupMessage.owned[0].args[1]].map((author) => {
      const id = library.CommitmentId.groupMessage(author);
      return [
        /^[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{22}$/.test(id),
        library.CommitmentId.isGroupMessageOf(id, author),
      ];
    }),
  };
};

const assertExpected = (runtime, result) => {
  const rejectedBearer =
    'error:InvalidBearerCapabilityError:Invalid bearer capability';
  const rejectedCommitment = 'error:InvalidCommitmentError:Invalid commitment';

  assert.deepEqual(
    result.hashes,
    bearer.hash.valid.map((item) => item.hash),
    runtime,
  );
  assert.deepEqual(
    result.rejectedTokens,
    bearer.hash.invalid.map(() => rejectedBearer),
    runtime,
  );
  assert.deepEqual(
    result.verified,
    bearer.verify.map((item) => item.expected),
    runtime,
  );
  assert.deepEqual(result.generated, [true, true], runtime);
  for (const section of Object.keys(owners)) {
    assert.deepEqual(
      result.sections[section].valid,
      commitments[section].valid.map((item) => item.id),
      runtime + ' ' + section,
    );
    assert.deepEqual(
      result.sections[section].invalid,
      commitments[section].invalid.map(() => rejectedCommitment),
      runtime + ' ' + section,
    );
  }
  assert.deepEqual(
    result.bytes,
    commitments.bytesDigest.valid.map((item) => item.id),
    runtime,
  );
  assert.deepEqual(
    result.groupMessages,
    [
      ...commitments.groupMessage.owned.map(() => true),
      ...commitments.groupMessage.foreign.map(() => false),
    ],
    runtime,
  );
  assert.deepEqual(result.created, [[true, true]], runtime);
};

(async () => {
  assertExpected(
    'node',
    evaluate(
      { BearerCapability, CommitmentId, StateDigest },
      bearer,
      commitments,
      owners,
    ),
  );
  const bundle = await build({
    stdin: {
      contents:
        "export { BearerCapability, CommitmentId, StateDigest } from './dist/index.js';",
      resolveDir: process.cwd(),
    },
    bundle: true,
    format: 'iife',
    globalName: 'PigeonCrypto',
    platform: 'browser',
    write: false,
  });
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', 'text/html');
    response.end(
      '<!doctype html><title>Disposable commitment interoperability test</title>',
    );
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    page.on('pageerror', (error) => console.error(error.message));
    await page.goto('http://127.0.0.1:' + server.address().port);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const result = await page.evaluate(
      ({ source, bearer, commitments, owners }) =>
        new Function('return ' + source)()(
          PigeonCrypto,
          bearer,
          commitments,
          owners,
        ),
      { source: evaluate.toString(), bearer, commitments, owners },
    );
    assertExpected('chromium', result);
    console.log(
      'PASS Node and bundled Chromium agree on bearer capabilities, commitment ids and state digests; invalid inputs are rejected.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
