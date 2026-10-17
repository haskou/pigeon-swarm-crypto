import * as crypto from 'node:crypto';

import { PreimageFields } from '../../src/internal/PreimageFields';
import { PublicKey, Signature } from '../../src';

const pair = crypto.generateKeyPairSync('ed25519');
const publicKey = new PublicKey(
  pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
);
const content = 'signed-preimage#68';
const honestSignature = Signature.fromBuffer(
  crypto.sign(null, Buffer.from(content), pair.privateKey),
);
const foreignSignature = Signature.fromBuffer(
  crypto.sign(
    null,
    Buffer.from(content),
    crypto.generateKeyPairSync('ed25519').privateKey,
  ),
);

describe('isValidSignature callers', () => {
  it.each([
    ['all zero', Buffer.alloc(64)],
    ['all ff', Buffer.alloc(64, 0xff)],
    ['identity R with zero S', Buffer.from(`01${'00'.repeat(63)}`, 'hex')],
  ])('returns false, never throws, for a %s signature', (_label, bytes) => {
    const signature = Signature.fromBuffer(bytes);

    expect(() => publicKey.isValidSignature(content, signature)).not.toThrow();
    expect(publicKey.isValidSignature(content, signature)).toBeFalse();
  });

  it('keeps PreimageFields.verify throwing on a false verification', () => {
    expect(() =>
      PreimageFields.verify(content, honestSignature, publicKey),
    ).not.toThrow();
    expect(() =>
      PreimageFields.verify(content, foreignSignature, publicKey),
    ).toThrow('Invalid preimage');
  });
});
