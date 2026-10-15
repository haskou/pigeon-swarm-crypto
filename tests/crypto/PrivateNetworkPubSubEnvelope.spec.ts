import { createCipheriv, createDecipheriv } from 'node:crypto';

import * as Crypto from '../../src';
import vectors from '../../vectors/private-network.json';

const keys = {
  network: Crypto.PrivateKey.fromPEM(vectors.keys.network.privateKeyPem),
  other: Crypto.PrivateKey.fromPEM(vectors.keys.other.privateKeyPem),
};
const pubsubKey = Buffer.from(vectors.derived.pubsubKeyHex, 'hex');
const { networkId, topic, payload } = vectors.pubsub;
const aad = (id: string, name: string): Buffer =>
  Buffer.from(
    `pigeon.private-network.pubsub.v2\0${JSON.stringify({ networkId: id, topic: name })}`,
  );
const invalid = expect.objectContaining({
  message: 'Invalid private network message',
  name: 'InvalidPrivateNetworkMessageError',
});
const nativeSeal = (plaintext: Buffer): string => {
  const nonce = Buffer.alloc(12, 9);
  const cipher = createCipheriv('aes-256-gcm', pubsubKey, nonce);
  cipher.setAAD(aad(networkId, topic));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
    cipher.getAuthTag(),
  ]);

  return JSON.stringify({
    ciphertext: ciphertext.toString('base64url'),
    nonce: nonce.toString('base64url'),
    version: 2,
  });
};

describe('PrivateNetworkPubSubEnvelope', () => {
  it('opens the shipped vector and binds the network id and topic', () => {
    expect(aad(networkId, topic).toString('utf8')).toBe(vectors.pubsub.aad);
    expect(
      Crypto.PrivateNetworkPubSubEnvelope.open(
        keys.network,
        networkId,
        topic,
        vectors.pubsub.envelope,
      ),
    ).toBe(payload);
  });

  it('seals canonical envelopes that an independent AES-256-GCM opens', () => {
    const envelope = Crypto.PrivateNetworkPubSubEnvelope.seal(
      keys.network,
      networkId,
      topic,
      payload,
    );
    const parsed = JSON.parse(envelope) as {
      ciphertext: string;
      nonce: string;
      version: number;
    };
    const sealed = Buffer.from(parsed.ciphertext, 'base64url');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      pubsubKey,
      Buffer.from(parsed.nonce, 'base64url'),
    );
    decipher.setAAD(aad(networkId, topic));
    decipher.setAuthTag(sealed.subarray(-16));

    expect(Object.keys(parsed)).toEqual(['ciphertext', 'nonce', 'version']);
    expect(parsed.version).toBe(2);
    expect(
      Buffer.concat([
        decipher.update(sealed.subarray(0, -16)),
        decipher.final(),
      ]).toString('utf8'),
    ).toBe(payload);
    expect(
      Crypto.PrivateNetworkPubSubEnvelope.seal(
        keys.network,
        networkId,
        topic,
        payload,
      ),
    ).not.toBe(envelope);
    expect(
      Crypto.PrivateNetworkPubSubEnvelope.open(
        keys.network,
        networkId,
        topic,
        Crypto.PrivateNetworkPubSubEnvelope.seal(
          keys.network,
          networkId,
          topic,
          '',
        ),
      ),
    ).toBe('');
  });

  it.each(vectors.pubsub.invalid.map((entry) => [entry.name, entry]))(
    'rejects %s',
    (_name, entry) => {
      expect(() =>
        Crypto.PrivateNetworkPubSubEnvelope.open(
          keys[entry.key as keyof typeof keys],
          entry.networkId,
          entry.topic,
          entry.envelope,
        ),
      ).toThrow(invalid);
    },
  );

  it('rejects malformed, oversized and non UTF-8 envelopes', () => {
    const open = (envelope: unknown): string =>
      Crypto.PrivateNetworkPubSubEnvelope.open(
        keys.network,
        networkId,
        topic,
        envelope as string,
      );
    const limit = Math.ceil(((1048576 + 16) * 4) / 3);

    for (const envelope of [
      undefined,
      1,
      'null',
      '{}',
      JSON.stringify({ ciphertext: 1, nonce: 'AAAAAAAAAAAAAAAA', version: 2 }),
      JSON.stringify({ ciphertext: 'AAAA', nonce: 1, version: 2 }),
      JSON.stringify({
        ciphertext: 'A'.repeat(20),
        nonce: 'AAAAAAAAAAAAAAAA',
        version: 2,
      }),
      JSON.stringify({
        ciphertext: 'A'.repeat(limit + 8),
        nonce: 'AAAAAAAAAAAAAAAA',
        version: 2,
      }),
      'x'.repeat(limit + 65),
      nativeSeal(Buffer.from([0xc3, 0x28])),
    ])
      expect(() => open(envelope)).toThrow(invalid);
  });

  it('accepts the largest payload and rejects one byte more', () => {
    const largest = 'a'.repeat(1048576);
    const envelope = Crypto.PrivateNetworkPubSubEnvelope.seal(
      keys.network,
      networkId,
      topic,
      largest,
    );

    expect(
      Crypto.PrivateNetworkPubSubEnvelope.open(
        keys.network,
        networkId,
        topic,
        envelope,
      ),
    ).toBe(largest);
    expect(() =>
      Crypto.PrivateNetworkPubSubEnvelope.seal(
        keys.network,
        networkId,
        topic,
        `${largest}a`,
      ),
    ).toThrow(invalid);
  });

  it('rejects invalid payloads, network ids and topics', () => {
    for (const value of [1, '\uD800'])
      expect(() =>
        Crypto.PrivateNetworkPubSubEnvelope.seal(
          keys.network,
          networkId,
          topic,
          value as string,
        ),
      ).toThrow(invalid);

    for (const name of [undefined, '', 'a'.repeat(1025), 'a\uDC00']) {
      for (const [id, scope] of [
        [name, topic],
        [networkId, name],
      ]) {
        expect(() =>
          Crypto.PrivateNetworkPubSubEnvelope.seal(
            keys.network,
            id as string,
            scope as string,
            payload,
          ),
        ).toThrow(invalid);
        expect(() =>
          Crypto.PrivateNetworkPubSubEnvelope.open(
            keys.network,
            id as string,
            scope as string,
            vectors.pubsub.envelope,
          ),
        ).toThrow(invalid);
      }
    }
    expect(
      Crypto.PrivateNetworkPubSubEnvelope.open(
        keys.network,
        'a'.repeat(1024),
        'b'.repeat(1024),
        Crypto.PrivateNetworkPubSubEnvelope.seal(
          keys.network,
          'a'.repeat(1024),
          'b'.repeat(1024),
          payload,
        ),
      ),
    ).toBe(payload);
  });

  it('requires a network private key', () => {
    expect(() =>
      Crypto.PrivateNetworkPubSubEnvelope.open(
        undefined as unknown as Crypto.PrivateKey,
        networkId,
        topic,
        vectors.pubsub.envelope,
      ),
    ).toThrow(Crypto.InvalidPrivateNetworkKeyError);
    expect(() =>
      Crypto.PrivateNetworkPubSubEnvelope.seal(
        undefined as unknown as Crypto.PrivateKey,
        networkId,
        topic,
        payload,
      ),
    ).toThrow(Crypto.InvalidPrivateNetworkKeyError);
  });
});
