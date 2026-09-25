import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { decodeMlsMessage, encodeMlsMessage } from 'ts-mls';
import { encodeGroupContext } from 'ts-mls/groupContext.js';

const fixture = JSON.parse(
  await readFile(
    new URL('../fixtures/mls-rfc9420-messages.json', import.meta.url),
    'utf8',
  ),
);

for (const [name, hex] of Object.entries(fixture.messages)) {
  const bytes = Uint8Array.from(Buffer.from(hex, 'hex'));
  const decoded = decodeMlsMessage(bytes, 0);

  assert.ok(decoded, name + ' did not decode');
  assert.equal(decoded[1], bytes.length, name + ' was not consumed exactly');
  assert.equal(
    Buffer.from(encodeMlsMessage(decoded[0])).toString('hex'),
    hex,
    name + ' did not preserve the RFC 9420 wire representation',
  );
}

const truncated = Uint8Array.from(
  Buffer.from(fixture.messages.mls_welcome.slice(0, -2), 'hex'),
);
assert.throws(() => decodeMlsMessage(truncated, 0));

const shared = JSON.parse(
  await readFile(
    new URL('../fixtures/private-delivery-vectors.json', import.meta.url),
    'utf8',
  ),
);
const groupContext = shared.groupContext;
const encodedContext = encodeGroupContext({
  cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
  confirmedTranscriptHash: Buffer.from(
    groupContext.confirmedTranscriptHashHex,
    'hex',
  ),
  epoch: BigInt(groupContext.epoch),
  extensions: [],
  groupId: Buffer.from(groupContext.groupIdHex, 'hex'),
  treeHash: Buffer.from(groupContext.treeHashHex, 'hex'),
  version: 'mls10',
});
assert.equal(Buffer.from(encodedContext).toString('hex'), groupContext.tlsHex);
assert.equal(
  createHash('sha256').update(encodedContext).digest('base64url'),
  groupContext.sha256,
);

console.log(
  'PASS pinned RFC 9420 messages and shared group-context vectors.',
);
