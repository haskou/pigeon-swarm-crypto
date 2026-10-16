const assert = require('node:assert/strict');
const { createServer } = require('node:http');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const api = require('../../dist');

const vectors = {
  backup: require('../../vectors/history-backup.json'),
  callMedia: require('../../vectors/call-media-frame.json'),
  draft: require('../../vectors/conversation-draft.json'),
  envelope: require('../../vectors/mailbox-envelope.json'),
  authorship: require('../../vectors/mailbox-record-authorship.json'),
  fingerprint: require('../../vectors/key-fingerprint.json'),
  readToken: require('../../vectors/mailbox-read-token.json'),
  recovery: require('../../vectors/recovery-kit.json'),
  rows: require('../../vectors/device-root-rows.json'),
  safety: require('../../vectors/safety-number.json'),
  schedule: require('../../vectors/mailbox-key-schedule.json'),
  unlock: require('../../vectors/device-unlock-factor.json'),
};

// Runs unchanged in Node, the Chromium page and a dedicated Worker. It returns
// deterministic outputs, values sealed with fresh randomness and the result of
// opening the values another runtime sealed.
async function exercise(api, vectors, peer) {
  const fromBase64 = (value) =>
    Uint8Array.from(atob(value.replace(/-/g, '+').replace(/_/g, '/')), (char) =>
      char.charCodeAt(0),
    );
  const toBase64Url = (bytes) => {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  };
  const utf8 = (value) => new TextEncoder().encode(value);
  const rejects = (operation) => {
    try {
      operation();
      return false;
    } catch {
      return true;
    }
  };
  const key = (value) => api.SymmetricKey.fromBase64(value);
  const message = 'Unicode: é 😀';
  const envelopeKeys = {
    envelopeKey: fromBase64(vectors.envelope.envelopeKey),
    mailboxId: vectors.envelope.mailboxId,
  };
  const envelopeId = vectors.envelope.seal[0].envelopeId;
  const [rowCase] = vectors.rows.cases;
  const rows = api.DeviceRootRowKeys.derive(
    key(rowCase.root),
    rowCase.label,
    rowCase.identityId,
  );
  const [draftCase] = vectors.draft.cases;
  const backupRoot = key(vectors.backup.root);
  const media = await api.CallMediaFrameCipher.fromKey(
    key(vectors.callMedia.key),
  );
  const keysOf = (keys) => ({
    envelopeKey: toBase64Url(keys.envelopeKey),
    mailboxId: keys.mailboxId,
    postToken: keys.postToken,
  });

  const deterministic = {
    schedule: vectors.schedule.derive.map((entry) =>
      keysOf(
        api.MailboxKeySchedule.derive(
          key(entry.sharedSecret),
          entry.recipientIdentityId,
          entry.epoch,
        ),
      ),
    ),
    contactPresence: vectors.schedule.contactPresence.map((entry) =>
      keysOf(
        api.MailboxKeySchedule.contactPresence(
          key(entry.conversationKey),
          entry.recipientIdentityId,
        ),
      ),
    ),
    groupInbox: vectors.schedule.groupInbox.map((entry) =>
      keysOf(
        api.MailboxKeySchedule.groupInbox(
          key(entry.generationSecret),
          entry.memberIdentityId,
        ),
      ),
    ),
    invalidGroupInbox: vectors.schedule.invalidGroupInbox.map((entry) =>
      rejects(() =>
        api.MailboxKeySchedule.groupInbox(
          key(vectors.schedule.groupInbox[0].generationSecret),
          entry.memberIdentityId,
        ),
      ),
    ),
    readTokens: [
      ...vectors.readToken.derive.map((entry) =>
        api.MailboxReadToken.derive(key(entry.rootKey), entry.mailboxId),
      ),
      ...vectors.readToken.deriveDevice.map((entry) =>
        api.MailboxReadToken.deriveDevice(
          key(entry.rootKey),
          entry.mailboxId,
          entry.deviceCredential,
        ),
      ),
    ],
    envelopes: vectors.envelope.seal.map((entry) =>
      toBase64Url(
        api.MailboxEnvelope.open(envelopeKeys, entry.envelopeId, entry.body),
      ),
    ),
    invalidEnvelopes: vectors.envelope.invalid.map((entry) =>
      rejects(() =>
        api.MailboxEnvelope.open(envelopeKeys, entry.envelopeId, entry.body),
      ),
    ),
    authorship: vectors.authorship.tags.map((entry) =>
      api.MailboxRecordAuthorship.tag(key(entry.rootKey), entry.record),
    ),
    invalidAuthorship: vectors.authorship.invalid.map((entry) =>
      api.MailboxRecordAuthorship.verify(
        key(entry.rootKey),
        entry.record,
        entry.tag,
      ),
    ),
    rows: vectors.rows.cases.map((entry) => {
      const keys = api.DeviceRootRowKeys.derive(
        key(entry.root),
        entry.label,
        entry.identityId,
      );
      return {
        canary: keys.opensCanary(fromBase64(entry.canary.sealed)),
        rows: entry.rows.map((row) =>
          toBase64Url(keys.open(row.purpose, row.scope, fromBase64(row.sealed))),
        ),
        tags: entry.tags.map((tag) => keys.tag(tag.parts)),
      };
    }),
    drafts: vectors.draft.cases.map((entry) => ({
      draftKey: api.ConversationDraft.draftKey(
        key(entry.root),
        entry.conversationId,
      ),
      opened: api.ConversationDraft.open(
        key(entry.root),
        entry.draftKey,
        entry.encryptedPayload,
      ),
    })),
    backups: vectors.backup.seal.map((entry) =>
      toBase64Url(
        api.HistoryBackupFile.open(
          backupRoot,
          vectors.backup.identityId,
          entry.file,
        ),
      ),
    ),
    recovery: vectors.recovery.derive.map((entry) => {
      const material = api.RecoveryKit.derive(
        api.RecoveryKey.fromString(entry.recoveryKey),
      );
      return {
        identity: material.identityKeyPair.toPrimitives(),
        authority: material.recoveryAuthorityKeyPair.toPrimitives(),
        root: material.rootKey.valueOf(),
      };
    }),
    unlock: await Promise.all(
      vectors.unlock.cases.map(async (entry) => {
        const factorKey = await globalThis.crypto.subtle.importKey(
          'raw',
          fromBase64(entry.factorKey),
          { hash: 'SHA-256', length: 256, name: 'HMAC' },
          false,
          ['sign'],
        );
        const factor = await api.DeviceUnlockFactor.derive(
          factorKey,
          entry.identityId,
          entry.deviceId,
          entry.secretHandle,
        );
        return [
          api.DeviceUnlockFactor.context(
            entry.identityId,
            entry.deviceId,
            entry.secretHandle,
          ),
          factor.valueOf(),
        ];
      }),
    ),
    safety: vectors.safety.cases.map((entry) =>
      api.SafetyNumber.between(entry.first, entry.second),
    ),
    fingerprints: [
      ...vectors.fingerprint.publicKeys.map((entry) =>
        api.KeyFingerprint.ofPublicKey(
          api.PublicKey.fromPEM(
            entry.publicKey.startsWith('-----BEGIN')
              ? entry.publicKey
              : `-----BEGIN PUBLIC KEY-----\n${entry.publicKey}\n-----END PUBLIC KEY-----\n`,
          ),
        ),
      ),
      ...vectors.fingerprint.publicBytes.map((entry) =>
        api.KeyFingerprint.ofPublicBytes(fromBase64(entry.bytes)),
      ),
      ...vectors.fingerprint.secrets.map((entry) =>
        api.KeyFingerprint.ofSecret(fromBase64(entry.secret)),
      ),
    ],
    frames: await Promise.all(
      vectors.callMedia.frames.map(async (entry) =>
        toBase64Url(await media.open(fromBase64(entry.frame))),
      ),
    ),
  };

  const sealed = {
    envelope: api.MailboxEnvelope.seal(envelopeKeys, envelopeId, utf8(message)),
    row: toBase64Url(
      rows.seal('record', ['conversation-1', 'record-1'], utf8(message)),
    ),
    canary: toBase64Url(rows.sealCanary()),
    draft: api.ConversationDraft.seal(
      key(draftCase.root),
      draftCase.conversationId,
      message,
    ),
    backup: api.HistoryBackupFile.seal(
      backupRoot,
      vectors.backup.identityId,
      utf8(message),
    ),
    frame: toBase64Url(await media.seal(utf8(message))),
    recoveryKey: api.RecoveryKey.generate().valueOf(),
  };

  const decode = (bytes) => new TextDecoder().decode(bytes);
  const opened = peer && {
    envelope: decode(
      api.MailboxEnvelope.open(envelopeKeys, envelopeId, peer.envelope),
    ),
    row: decode(
      rows.open(
        'record',
        ['conversation-1', 'record-1'],
        fromBase64(peer.row),
      ),
    ),
    canary: rows.opensCanary(fromBase64(peer.canary)),
    draft: api.ConversationDraft.open(
      key(draftCase.root),
      api.ConversationDraft.draftKey(
        key(draftCase.root),
        draftCase.conversationId,
      ),
      peer.draft,
    ).content,
    backup: decode(
      api.HistoryBackupFile.open(
        backupRoot,
        vectors.backup.identityId,
        peer.backup,
      ),
    ),
    frame: decode(await media.open(fromBase64(peer.frame))),
    recoveryKey: api.RecoveryKey.isValid(peer.recoveryKey),
  };

  return { deterministic, sealed, opened };
}

const expectedOpened = {
  envelope: 'Unicode: é 😀',
  row: 'Unicode: é 😀',
  canary: true,
  draft: 'Unicode: é 😀',
  backup: 'Unicode: é 😀',
  frame: 'Unicode: é 😀',
  recoveryKey: true,
};

(async () => {
  const node = await exercise(api, vectors, undefined);
  assert.deepEqual(
    node.deterministic.groupInbox,
    vectors.schedule.groupInbox.map(({ envelopeKey, mailboxId, postToken }) => ({
      envelopeKey,
      mailboxId,
      postToken,
    })),
  );
  assert.ok(node.deterministic.invalidGroupInbox.every(Boolean));
  const bundle = await build({
    stdin: {
      contents: "export * from './dist/index.js';",
      resolveDir: process.cwd(),
    },
    bundle: true,
    format: 'iife',
    globalName: 'PigeonCrypto',
    platform: 'browser',
    write: false,
  });
  const bundleText = bundle.outputFiles[0].text;
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', 'text/html');
    response.end('<!doctype html><title>Client key schedule runtime test</title>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    page.on('pageerror', (error) => console.error(error.message));
    await page.goto('http://127.0.0.1:' + server.address().port);
    await page.addScriptTag({ content: bundleText });
    const source = exercise.toString();
    const chromiumResult = await page.evaluate(
      async ({ source, vectors, peer }) =>
        // eslint-disable-next-line no-new-func
        new Function(`return (${source})`)()(PigeonCrypto, vectors, peer),
      { source, vectors, peer: node.sealed },
    );
    const workerResult = await page.evaluate(
      ({ bundleText, source, vectors, peer }) =>
        new Promise((resolve, reject) => {
          const code = `${bundleText}
self.onmessage = async (event) => {
  try {
    const value = await (${source})(PigeonCrypto, event.data.vectors, event.data.peer);
    self.postMessage({ value });
  } catch (error) {
    self.postMessage({ error: String((error && error.stack) || error) });
  }
};`;
          const url = URL.createObjectURL(
            new Blob([code], { type: 'text/javascript' }),
          );
          const worker = new Worker(url);
          worker.onerror = (event) => reject(new Error(event.message));
          worker.onmessage = (event) => {
            worker.terminate();
            URL.revokeObjectURL(url);
            if (event.data.error) reject(new Error(event.data.error));
            else resolve(event.data.value);
          };
          worker.postMessage({ vectors, peer });
        }),
      { bundleText, source, vectors, peer: node.sealed },
    );

    for (const result of [chromiumResult, workerResult]) {
      assert.deepEqual(result.deterministic, node.deterministic);
      assert.deepEqual(result.opened, expectedOpened);
      assert.deepEqual(
        (await exercise(api, vectors, result.sealed)).opened,
        expectedOpened,
      );
    }
    assert.notEqual(chromiumResult.sealed.envelope, node.sealed.envelope);
    assert.notEqual(workerResult.sealed.frame, node.sealed.frame);
    console.log(
      'PASS Node, Chromium and a Chromium Worker agree on client key schedules and open each other\'s sealed values.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
