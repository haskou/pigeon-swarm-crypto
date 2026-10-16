const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const api = require('../../dist');
const vectors = require('../../vectors/group-mailbox-control-letter.json');

// Runs unchanged in Node and the Chromium page. It returns the letters it
// could open, the rejections and a letter it sealed for the other runtime.
function exercise(api, vectors, peer) {
  const fromBase64Url = (value) =>
    Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (char) =>
      char.charCodeAt(0),
    );
  const key = (name) =>
    api.PrivateKey.fromPEM(vectors.keys[name].privateKeyPem);
  const sender = key('sender');
  const recipient = key('recipient');
  const senderId = vectors.keys.sender.identityId;
  const attempt = (operation) => {
    try {
      return operation();
    } catch (error) {
      return 'error:' + error.name + ':' + error.message;
    }
  };
  const view = (opened) => ({
    conversationId: opened.conversationId,
    payload: Array.from(opened.payload),
    sentAt: opened.sentAt,
  });
  const inputOf = (letter) => ({
    conversationId: letter.conversationId,
    payload: Uint8Array.from(fromBase64Url(letter.payload)),
    recipientIdentityId: letter.recipientIdentityId,
    sentAt: letter.sentAt,
  });

  return {
    signingContent: vectors.valid.map((item) =>
      api.GroupMailboxControlLetter.signingContent(item.letter),
    ),
    opened: vectors.valid.map((item) =>
      view(
        api.GroupMailboxControlLetter.open(recipient, item.sealed, senderId),
      ),
    ),
    invalidOpen: vectors.invalidOpen.map((item) =>
      attempt(() =>
        api.GroupMailboxControlLetter.open(
          recipient,
          item.sealed,
          item.senderIdentityId,
        ),
      ),
    ),
    invalidSeal: vectors.invalidSeal.map((item) =>
      attempt(() =>
        api.GroupMailboxControlLetter.seal(sender, inputOf(item.letter)),
      ),
    ),
    sealed: vectors.valid.map((item) =>
      api.GroupMailboxControlLetter.seal(sender, inputOf(item.letter)),
    ),
    peerOpened: (peer ?? []).map((sealed) =>
      view(api.GroupMailboxControlLetter.open(recipient, sealed, senderId)),
    ),
  };
}

const rejected =
  'error:InvalidGroupMailboxControlLetterError:Invalid group mailbox control letter';
const expectedOpened = vectors.valid.map((item) => ({
  conversationId: item.letter.conversationId,
  payload: Array.from(Buffer.from(item.letter.payload, 'base64url')),
  sentAt: item.letter.sentAt,
}));

const assertExpected = (runtime, result) => {
  assert.deepEqual(
    result.signingContent,
    vectors.valid.map((item) => item.signingContent),
    runtime,
  );
  assert.deepEqual(result.opened, expectedOpened, runtime);
  assert.deepEqual(
    result.invalidOpen,
    vectors.invalidOpen.map(() => rejected),
    runtime,
  );
  assert.deepEqual(
    result.invalidSeal,
    vectors.invalidSeal.map(() => rejected),
    runtime,
  );
  const recipient = api.PrivateKey.fromPEM(
    vectors.keys.recipient.privateKeyPem,
  );
  assert.deepEqual(
    result.sealed.map((sealed) =>
      recipient.decrypt(new api.EncryptedPayload(sealed)).toString(),
    ),
    vectors.valid.map((item) => item.sealedPlaintext),
    runtime,
  );
};

(async () => {
  const node = exercise(api, vectors, undefined);
  assertExpected('node', node);
  const bundle = await build({
    stdin: {
      contents:
        "export { EncryptedPayload, GroupMailboxControlLetter, PrivateKey } from './dist/index.js';",
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
      '<!doctype html><title>Group mailbox control letter runtime test</title>',
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
      ({ source, vectors, peer }) =>
        // eslint-disable-next-line no-new-func
        new Function('return ' + source)()(PigeonCrypto, vectors, peer),
      { source: exercise.toString(), vectors, peer: node.sealed },
    );
    assertExpected('chromium', result);
    assert.deepEqual(result.peerOpened, expectedOpened, 'chromium opens node');
    assert.deepEqual(
      exercise(api, vectors, result.sealed).peerOpened,
      expectedOpened,
      'node opens chromium',
    );
    console.log(
      "PASS Node and bundled Chromium agree on group mailbox control letters, open each other's letters and reject invalid ones.",
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
