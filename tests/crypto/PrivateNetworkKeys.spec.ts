import { NullObject } from '@haskou/value-objects';
import { createHash, hkdfSync } from 'node:crypto';

import * as Crypto from '../../src';
import vectors from '../../vectors/private-network.json';

const seed = createHash('sha256')
  .update('pigeon-vector:private-network')
  .digest();
const networkKey = Crypto.PrivateKey.fromPEM(
  vectors.keys.network.privateKeyPem,
);
const otherKey = Crypto.PrivateKey.fromPEM(vectors.keys.other.privateKeyPem);
const derive = (label: string, length: number): Buffer =>
  Buffer.from(hkdfSync('sha256', seed, Buffer.alloc(0), label, length));

describe('PrivateNetworkKeys', () => {
  it('derives the shipped vectors with HKDF-SHA256 over the network seed', () => {
    expect(seed.toString('hex')).toBe(vectors.keys.network.seedHex);
    expect(Crypto.PrivateKey.fromSeed(seed).valueOf()).toBe(
      vectors.keys.network.privateKeyPem,
    );
    expect(Crypto.PrivateNetworkKeys.fingerprint(networkKey)).toBe(
      derive('pigeon.private-network.fingerprint.v2', 12).toString('base64url'),
    );
    expect(Crypto.PrivateNetworkKeys.fingerprint(networkKey)).toBe(
      vectors.derived.fingerprint,
    );
    expect(Crypto.PrivateNetworkKeys.relayLookupKey(networkKey)).toBe(
      `pigeon-swarm/private-relays/v2/${derive(
        'pigeon.private-network.relay-lookup.v2',
        32,
      ).toString('base64url')}`,
    );
    expect(Crypto.PrivateNetworkKeys.relayLookupKey(networkKey)).toBe(
      vectors.derived.relayLookupKey,
    );
    const swarmKey = Crypto.PrivateNetworkKeys.swarmKey(networkKey);

    expect(swarmKey).toBeInstanceOf(Uint8Array);
    expect(Buffer.from(swarmKey).toString('utf8')).toBe(
      `/key/swarm/psk/1.0.0/\n/base16/\n${derive(
        'pigeon.private-network.swarm-psk.v2',
        32,
      ).toString('hex')}`,
    );
    expect(Buffer.from(swarmKey).toString('utf8')).toBe(
      vectors.derived.swarmKey,
    );
  });

  it('separates every derivation by network key and by label', () => {
    expect(Crypto.PrivateNetworkKeys.fingerprint(otherKey)).toBe(
      vectors.otherDerived.fingerprint,
    );
    expect(Crypto.PrivateNetworkKeys.relayLookupKey(otherKey)).toBe(
      vectors.otherDerived.relayLookupKey,
    );
    expect(
      Buffer.from(Crypto.PrivateNetworkKeys.swarmKey(otherKey)).toString(),
    ).toBe(vectors.otherDerived.swarmKey);
    const outputs = [
      vectors.derived.fingerprint,
      vectors.derived.pubsubKeyHex,
      vectors.derived.relayLookupKey,
      vectors.derived.relayRecordKeyHex,
      vectors.derived.swarmPskHex,
      vectors.otherDerived.fingerprint,
      vectors.otherDerived.relayLookupKey,
      vectors.otherDerived.swarmKey,
    ];

    expect(new Set(outputs).size).toBe(outputs.length);
    expect(vectors.derived.relayLookupKey).not.toContain(
      createHash('sha256').update(seed).digest('base64url'),
    );
  });

  it('rejects anything but a network private key', () => {
    for (const key of [
      NullObject.new(Crypto.PrivateKey),
      Crypto.PrivateKey.generate().getPublicKey(),
      undefined,
    ]) {
      const networkKey = key as unknown as Crypto.PrivateKey;

      for (const derivation of [
        () => Crypto.PrivateNetworkKeys.fingerprint(networkKey),
        () => Crypto.PrivateNetworkKeys.relayLookupKey(networkKey),
        () => Crypto.PrivateNetworkKeys.swarmKey(networkKey),
      ]) {
        expect(derivation).toThrow(
          expect.objectContaining({
            message: 'Invalid private network key',
            name: 'InvalidPrivateNetworkKeyError',
          }),
        );
      }
    }
  });
});
