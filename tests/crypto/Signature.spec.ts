import { NullObject, StringValueObject } from '@haskou/value-objects';
import * as crypto from 'node:crypto';

import { InvalidSignatureError, PublicKey, Signature } from '../../src';
import { VectorKey, loadVectors, privateKeyOf, publicKeyOf } from '../vectors';

const BASE64 =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const KNOWN_CONTENT = 'pigeon-swarm-crypto#55';
const KNOWN_SIGNATURE =
  'SfqlnJraI11O7qLpyiBm8BZT2q8RwuLRCyDuNfqybTnahhL+V2Otm8JhN+1mbxreRx53Vg3zThpussoy/5/PBw==';
const creator = loadVectors<{ keys: { creator: VectorKey } }>('call-event').keys
  .creator;
const nonCanonicalVariants = (signature: string): string[] =>
  BASE64.split('')
    .filter((character) => character !== signature[85])
    .map((character) => `${signature.slice(0, 85)}${character}==`)
    .filter((variant) =>
      Buffer.from(variant, 'base64').equals(Buffer.from(signature, 'base64')),
    );

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

  it('accepts and verifies the known-answer signature of a fixture key', () => {
    const signature = new Signature(KNOWN_SIGNATURE);

    expect(privateKeyOf(creator).sign(KNOWN_CONTENT).valueOf()).toBe(
      KNOWN_SIGNATURE,
    );
    expect(
      publicKeyOf(creator).isValidSignature(KNOWN_CONTENT, signature),
    ).toBeTrue();
  });

  it('rejects all 15 non-canonical encodings of the last data character', () => {
    const variants = nonCanonicalVariants(KNOWN_SIGNATURE);

    expect(variants).toHaveLength(15);
    variants.forEach((variant) =>
      expect(() => new Signature(variant)).toThrow(InvalidSignatureError),
    );
  });

  it('never lets PublicKey.isValidSignature see a non-canonical encoding', () => {
    const key: PublicKey = publicKeyOf(creator);
    const verify = jest.spyOn(key, 'isValidSignature');

    nonCanonicalVariants(KNOWN_SIGNATURE).forEach((variant) =>
      expect(() =>
        key.isValidSignature(KNOWN_CONTENT, new Signature(variant)),
      ).toThrow(InvalidSignatureError),
    );
    expect(verify).not.toHaveBeenCalled();
  });
});
