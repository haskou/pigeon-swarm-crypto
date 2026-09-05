import {
  InvalidFormatError,
  InvalidLengthError,
  Media,
  NullObject,
  StringValueObject,
} from '@haskou/value-objects';
import * as crypto from 'node:crypto';

import {
  AsymmetricEncryptedPayload,
  EncryptedPayload,
  Key,
  PrivateKey,
  PublicKey,
  Signature,
} from '../../src';

describe('PublicKey', () => {
  let privatePem: string;
  let publicPem: string;

  beforeAll(() => {
    const pair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    privatePem = pair.privateKey;
    publicPem = pair.publicKey;
  });

  it('validates constructor input', () => {
    expect(
      NullObject.isNullObject(new PublicKey(undefined as unknown as string)),
    ).toBeTrue();
    expect(
      NullObject.isNullObject(new PublicKey(null as unknown as string)),
    ).toBeTrue();
    expect(new PublicKey(publicPem).valueOf()).toBe(publicPem);
    expect(() => new PublicKey('short')).toThrow(InvalidLengthError);
    expect(() => new PublicKey('a'.repeat(113))).toThrow(InvalidFormatError);
    expect(() => new PublicKey(privatePem)).toThrow(InvalidLengthError);
  });

  it('creates keys from PEM strings and VOs', () => {
    expect(PublicKey.fromPEM(publicPem).valueOf()).toBe(publicPem);
    expect(
      PublicKey.fromPEM(new StringValueObject(publicPem)).valueOf(),
    ).toBe(publicPem);
  });

  it('verifies valid signatures and rejects invalid ones', () => {
    const key = new PublicKey(publicPem);
    const valid = Signature.fromBuffer(
      crypto.sign(null, Buffer.from('message'), privatePem),
    );
    const invalid = Signature.fromBuffer(
      crypto.sign(null, Buffer.from('other'), privatePem),
    );

    expect(key.isValidSignature('message', valid)).toBeTrue();
    expect(key.isValidSignature('tampered', valid)).toBeFalse();
    expect(key.isValidSignature('message', invalid)).toBeFalse();
    expect(
      key.isValidSignature(new StringValueObject('message'), valid),
    ).toBeTrue();
  });

  it('verifies signatures over raw Media bytes', () => {
    const payload = Buffer.from([0xff, 0xfe, 0xfd, 0, 0x80]);
    const signature = Signature.fromBuffer(
      crypto.sign(null, payload, privatePem),
    );
    expect(
      new PublicKey(publicPem).isValidSignature(new Media(payload), signature),
    ).toBeTrue();
  });

  it('encrypts versioned payloads with fresh ephemeral keys and IVs', () => {
    const key = new PublicKey(publicPem);
    const first = key.encrypt('same payload');
    const second = key.encrypt('same payload');
    const parts = first.valueOf().split('.');

    expect(first).toBeInstanceOf(AsymmetricEncryptedPayload);
    expect(first).toBeInstanceOf(EncryptedPayload);
    expect(first.getScheme()).toBe('asymmetric');
    expect(parts).toHaveLength(6);
    expect(parts[0]).toBe('v2');
    expect(parts[1]).toBe('x25519-hkdf-sha256-aes-256-gcm');
    expect(Buffer.from(parts[2], 'base64')).toHaveLength(32);
    expect(Buffer.from(parts[3], 'base64')).toHaveLength(12);
    expect(Buffer.from(parts[5], 'base64')).toHaveLength(16);
    expect(parts[2]).not.toBe(second.valueOf().split('.')[2]);
    expect(parts[3]).not.toBe(second.valueOf().split('.')[3]);
  });

  it('encrypts VO and Media payloads and round-trips through PrivateKey', () => {
    const pub = new PublicKey(publicPem);
    const priv = new PrivateKey(privatePem);
    const vo = pub.encrypt(new StringValueObject('hello'));
    const bytes = Buffer.from([0xff, 0xfe, 0xfd, 0, 0x80]);
    const media = pub.encrypt(new Media(bytes));

    expect(priv.decrypt(vo).toString()).toBe('hello');
    expect(priv.decrypt(media)).toEqual(bytes);
  });

  it('rejects oversized payloads', () => {
    expect(() =>
      new PublicKey(publicPem).encrypt(Buffer.alloc(1024 * 1024 + 1)),
    ).toThrow(InvalidLengthError);
  });

  it('keeps Key and ValueObject behavior', () => {
    const first = new PublicKey(publicPem);
    const second = new PublicKey(publicPem);
    const cloned = (first as any).clone();
    const other = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });

    expect(first).toBeInstanceOf(Key);
    expect(first.isEqual(second)).toBeTrue();
    expect(first.isEqual(publicPem)).toBeTrue();
    expect(first.isEqual(new PublicKey(other.publicKey))).toBeFalse();
    expect(cloned).toBeInstanceOf(PublicKey);
    expect(cloned.valueOf()).toBe(publicPem);
    expect(cloned).not.toBe(first);
  });
});
