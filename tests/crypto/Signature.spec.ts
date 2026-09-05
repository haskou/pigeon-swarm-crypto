import { NullObject, StringValueObject } from '@haskou/value-objects';
import * as crypto from 'node:crypto';

import { InvalidSignatureError, Signature } from '../../src';

describe('Signature', () => {
  let validSignatureBase64: string;

  beforeAll(() => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    validSignatureBase64 = crypto
      .sign(null, Buffer.from('test'), privateKey)
      .toString('base64');
  });

  it('handles nullish values', () => {
    expect(
      NullObject.isNullObject(new Signature(undefined as unknown as string)),
    ).toBeTrue();
    expect(
      NullObject.isNullObject(new Signature(null as unknown as string)),
    ).toBeTrue();
  });

  it('accepts valid signatures and StringValueObject input', () => {
    expect(validSignatureBase64).toHaveLength(88);
    expect(new Signature(validSignatureBase64).valueOf()).toBe(
      validSignatureBase64,
    );
    expect(
      new Signature(new StringValueObject(validSignatureBase64)).valueOf(),
    ).toBe(validSignatureBase64);
  });

  it('rejects invalid lengths and characters', () => {
    expect(() => new Signature('short')).toThrow(InvalidSignatureError);
    expect(() => new Signature('a'.repeat(87))).toThrow(InvalidSignatureError);
    expect(() => new Signature('a'.repeat(89))).toThrow(InvalidSignatureError);
    expect(() => new Signature('!' + 'A'.repeat(84) + '==')).toThrow(
      InvalidSignatureError,
    );
    expect(() => new Signature(new StringValueObject('short'))).toThrow(
      InvalidSignatureError,
    );
  });

  it('creates signatures from buffers', () => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    const sigBuffer = crypto.sign(null, Buffer.from('data'), privateKey);
    const sig = Signature.fromBuffer(sigBuffer);

    expect(sigBuffer).toHaveLength(64);
    expect(sig).toBeInstanceOf(Signature);
    expect(sig.valueOf()).toBe(sigBuffer.toString('base64'));
  });

  it('keeps ValueObject behavior', () => {
    const first = new Signature(validSignatureBase64);
    const second = new Signature(validSignatureBase64);
    const { privateKey } = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    const different = Signature.fromBuffer(
      crypto.sign(null, Buffer.from('other'), privateKey),
    );
    const cloned = (first as any).clone();

    expect(first.valueOf()).toBe(validSignatureBase64);
    expect(first.toString()).toBe(validSignatureBase64);
    expect(first.isEqual(second)).toBeTrue();
    expect(first.isEqual(validSignatureBase64)).toBeFalse();
    expect(first.hasValue(validSignatureBase64)).toBeTrue();
    expect(first.isEqual(different)).toBeFalse();
    expect(cloned).toBeInstanceOf(Signature);
    expect(cloned.isEqual(first)).toBeTrue();
    expect(cloned).not.toBe(first);
  });
});
