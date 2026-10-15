import { createDecipheriv } from 'node:crypto';

import * as Crypto from '../../src';
import vectors from '../../vectors/private-network.json';

const keys = {
  network: Crypto.PrivateKey.fromPEM(vectors.keys.network.privateKeyPem),
  other: Crypto.PrivateKey.fromPEM(vectors.keys.other.privateKeyPem),
};
const relayKey = Buffer.from(vectors.derived.relayRecordKeyHex, 'hex');
const record = vectors.relayRecord.record as Crypto.PrivateNetworkRelayRecord;
const invalid = expect.objectContaining({
  message: 'Invalid private network relay record',
  name: 'InvalidPrivateNetworkRelayRecordError',
});

describe('PrivateNetworkRelayRecordEnvelope', () => {
  it('opens the shipped vector into a frozen record', () => {
    const opened = Crypto.PrivateNetworkRelayRecordEnvelope.open(
      keys.network,
      vectors.relayRecord.envelope,
    );

    expect(opened).toEqual(record);
    expect(Object.isFrozen(opened)).toBe(true);
    expect(Object.isFrozen(opened.multiaddrs)).toBe(true);
  });

  it('seals the canonical record so an independent AES-256-GCM opens it', () => {
    const envelope = Crypto.PrivateNetworkRelayRecordEnvelope.seal(
      keys.network,
      record,
    );
    const parsed = JSON.parse(envelope) as {
      ciphertext: string;
      nonce: string;
    };
    const sealed = Buffer.from(parsed.ciphertext, 'base64url');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      relayKey,
      Buffer.from(parsed.nonce, 'base64url'),
    );
    decipher.setAAD(Buffer.from(vectors.relayRecord.aad));
    decipher.setAuthTag(sealed.subarray(-16));

    expect(
      Buffer.concat([
        decipher.update(sealed.subarray(0, -16)),
        decipher.final(),
      ]).toString('utf8'),
    ).toBe(vectors.relayRecord.plaintext);
    expect(
      Crypto.PrivateNetworkRelayRecordEnvelope.open(keys.network, envelope),
    ).toEqual(record);
  });

  it.each(vectors.relayRecord.invalid.map((entry) => [entry.name, entry]))(
    'rejects %s',
    (_name, entry) => {
      expect(() =>
        Crypto.PrivateNetworkRelayRecordEnvelope.open(
          keys[entry.key as keyof typeof keys],
          entry.envelope,
        ),
      ).toThrow(invalid);
    },
  );

  it('rejects invalid records before sealing', () => {
    const multiaddr = '/ip4/203.0.113.7/tcp/4001';

    for (const value of [
      undefined,
      null,
      [],
      { ...record, extra: true },
      { ...record, issuedAt: 1.5 },
      { ...record, expiresAt: '1' },
      { ...record, issuedAt: -1 },
      { ...record, expiresAt: record.issuedAt },
      { ...record, multiaddrs: 'x' },
      { ...record, multiaddrs: [] },
      { ...record, multiaddrs: Array(33).fill(multiaddr) },
      { ...record, multiaddrs: [1] },
      { ...record, multiaddrs: [''] },
      { ...record, multiaddrs: ['a'.repeat(1025)] },
      { ...record, multiaddrs: ['\uD800'] },
      { ...record, peerId: 'a'.repeat(129) },
      { ...record, role: 'call-relay' },
      { ...record, version: 2 },
      { ...record, multiaddrs: Array(9).fill('a'.repeat(1024)) },
    ])
      expect(() =>
        Crypto.PrivateNetworkRelayRecordEnvelope.seal(
          keys.network,
          value as unknown as Crypto.PrivateNetworkRelayRecord,
        ),
      ).toThrow(invalid);
  });

  it('requires a network private key', () => {
    for (const operation of [
      () =>
        Crypto.PrivateNetworkRelayRecordEnvelope.open(
          undefined as unknown as Crypto.PrivateKey,
          vectors.relayRecord.envelope,
        ),
      () =>
        Crypto.PrivateNetworkRelayRecordEnvelope.seal(
          undefined as unknown as Crypto.PrivateKey,
          record,
        ),
    ])
      expect(operation).toThrow(Crypto.InvalidPrivateNetworkKeyError);
  });
});
