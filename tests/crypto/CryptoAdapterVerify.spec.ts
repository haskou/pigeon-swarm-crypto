import * as crypto from 'node:crypto';

import { CryptoAdapter } from '../../src/internal/CryptoAdapter';

const message = Buffer.from('pigeon-swarm-crypto#68');
const pair = crypto.generateKeyPairSync('ed25519');
const publicPem = pair.publicKey
  .export({ format: 'pem', type: 'spki' })
  .toString();
const signature = crypto.sign(null, message, pair.privateKey);
const raw = Buffer.from(
  pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32),
);
const pemOf = (body: string): string =>
  `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;
const der = Buffer.from(pair.publicKey.export({ format: 'der', type: 'spki' }));
const ORDER = 2n ** 252n + 27742317777372353535851937790883648493n;
const littleEndian = (value: bigint): Buffer => {
  const bytes = Buffer.alloc(32);
  let rest = value;

  for (let index = 0; index < 32; index += 1) {
    bytes[index] = Number(rest % 256n);
    rest /= 256n;
  }

  return bytes;
};
const scalarOf = (bytes: Buffer): bigint =>
  bytes.reduceRight((value, byte) => value * 256n + BigInt(byte), 0n);
const identityKey = Buffer.from(`01${'00'.repeat(31)}`, 'hex');
const orderTwoKey = Buffer.from(`ec${'ff'.repeat(30)}7f`, 'hex');
const nonCanonicalIdentityKey = Buffer.from(`ee${'ff'.repeat(30)}7f`, 'hex');
const identitySignature = Buffer.from(`01${'00'.repeat(63)}`, 'hex');
const nonCanonicalR = Buffer.concat([
  Buffer.from(`ed${'ff'.repeat(30)}7f`, 'hex'),
  signature.subarray(32),
]);
const nonCanonicalS = Buffer.concat([
  signature.subarray(0, 32),
  littleEndian(scalarOf(signature.subarray(32)) + ORDER),
]);

describe('CryptoAdapter.verify', () => {
  it('verifies a canonical PEM and a raw 32-byte key', () => {
    expect(CryptoAdapter.verify(signature, message, publicPem)).toBe(true);
    expect(CryptoAdapter.verify(signature, message, raw)).toBe(true);
  });

  it('returns false for a well-formed key that did not sign the message', () => {
    expect(
      CryptoAdapter.verify(signature, Buffer.from('other'), publicPem),
    ).toBe(false);
  });

  it.each([
    ['empty input', ''],
    ['text without PEM framing', 'not a pem'],
    ['invalid base64 body', pemOf('!!!!')],
    ['truncated body', publicPem.slice(0, -20)],
    ['body shorter than a key', pemOf(der.toString('base64').slice(0, 20))],
    ['body longer than a key', pemOf(`${der.toString('base64')}AAAA`)],
    [
      'wrong DER prefix',
      pemOf(Buffer.concat([Buffer.alloc(12), raw]).toString('base64')),
    ],
    ['missing trailing newline', publicPem.trimEnd()],
  ])('returns false for a malformed PEM: %s', (_label, pem) => {
    expect(() => CryptoAdapter.verify(signature, message, pem)).not.toThrow();
    expect(CryptoAdapter.verify(signature, message, pem)).toBe(false);
  });

  it('returns false for a raw key that is not 32 bytes', () => {
    expect(CryptoAdapter.verify(signature, message, raw.subarray(1))).toBe(
      false,
    );
  });

  it('returns false for a signature that is not 64 bytes', () => {
    expect(
      CryptoAdapter.verify(signature.subarray(1), message, publicPem),
    ).toBe(false);
  });

  describe('raw-key vectors (RFC 8032 strict verification)', () => {
    it.each([
      ['small-order identity key', identityKey],
      ['small-order order-two key', orderTwoKey],
      ['non-canonical identity key', nonCanonicalIdentityKey],
    ])('rejects a %s for every signature', (_label, key) => {
      for (const candidate of [identitySignature, signature])
        for (const payload of [message, Buffer.from('other'), Buffer.alloc(0)])
          expect(CryptoAdapter.verify(candidate, payload, key)).toBe(false);
    });

    it('rejects a non-canonical S (S + L) under the honest key', () => {
      expect(CryptoAdapter.verify(nonCanonicalS, message, raw)).toBe(false);
      expect(CryptoAdapter.verify(nonCanonicalS, message, publicPem)).toBe(
        false,
      );
    });

    it('rejects a non-canonical R (y = p) under the honest key', () => {
      expect(CryptoAdapter.verify(nonCanonicalR, message, raw)).toBe(false);
      expect(CryptoAdapter.verify(nonCanonicalR, message, publicPem)).toBe(
        false,
      );
    });
  });
});
