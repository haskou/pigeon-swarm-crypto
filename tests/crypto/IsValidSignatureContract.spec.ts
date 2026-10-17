import * as crypto from 'node:crypto';

import { PreimageFields } from '../../src/internal/PreimageFields';
import { InvalidMlsCredentialError } from '../../src/mls/InvalidMlsCredentialError';
import { MlsLeafCredential } from '../../src/mls/MlsLeafCredential';
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

describe('MlsLeafCredential.verify caller contract', () => {
  const pem = (key: crypto.KeyObject): string =>
    key.export({ format: 'pem', type: 'spki' }).toString();
  const body = (key: crypto.KeyObject): string =>
    key.export({ format: 'der', type: 'spki' }).toString('base64');
  const sign = (key: crypto.KeyObject, text: string): string =>
    crypto.sign(null, Buffer.from(text), key).toString('base64');
  const identity = crypto.generateKeyPairSync('ed25519');
  const device = crypto.generateKeyPairSync('ed25519');
  const foreign = crypto.generateKeyPairSync('ed25519');
  const signaturePublicKey = Buffer.alloc(32, 7);
  const owner = {
    deviceCredential: pem(device.publicKey),
    identityId: body(identity.publicKey),
  };
  const signerWith = (
    identitySigner: crypto.KeyObject,
    deviceSigner: crypto.KeyObject,
  ) => ({
    owner,
    sign: (text: string) => ({
      device: sign(deviceSigner, text),
      identity: sign(identitySigner, text),
    }),
  });

  it('accepts a credential both keys signed', () => {
    const credential = MlsLeafCredential.issue(
      signerWith(identity.privateKey, device.privateKey),
      signaturePublicKey,
    );

    expect(MlsLeafCredential.verify(credential, signaturePublicKey)).toEqual(
      owner,
    );
  });

  it('throws InvalidMlsCredentialError when the device signature is foreign', () => {
    const credential = MlsLeafCredential.issue(
      signerWith(identity.privateKey, foreign.privateKey),
      signaturePublicKey,
    );

    expect(() =>
      MlsLeafCredential.verify(credential, signaturePublicKey),
    ).toThrow(InvalidMlsCredentialError);
  });

  it('throws InvalidMlsCredentialError when the identity signature is foreign', () => {
    const credential = MlsLeafCredential.issue(
      signerWith(foreign.privateKey, device.privateKey),
      signaturePublicKey,
    );

    expect(() =>
      MlsLeafCredential.verify(credential, signaturePublicKey),
    ).toThrow(InvalidMlsCredentialError);
  });
});
