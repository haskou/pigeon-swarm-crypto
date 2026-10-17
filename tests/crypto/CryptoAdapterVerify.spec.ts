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
});
