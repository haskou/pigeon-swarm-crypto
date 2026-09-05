import {
  InvalidFormatError,
  InvalidLengthError,
  Media,
  NullObject,
  StringValueObject,
} from '@haskou/value-objects';
import * as crypto from 'node:crypto';

import {
  EncryptedPayload,
  Key,
  PrivateKey,
  PublicKey,
  Signature,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';

describe('PrivateKey', () => {
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

  it('validates constructor input and factories', () => {
    expect(
      NullObject.isNullObject(new PrivateKey(undefined as unknown as string)),
    ).toBeTrue();
    expect(
      NullObject.isNullObject(new PrivateKey(null as unknown as string)),
    ).toBeTrue();
    expect(new PrivateKey(privatePem).valueOf()).toBe(privatePem);
    expect(() => new PrivateKey('short')).toThrow(InvalidLengthError);
    expect(() => new PrivateKey('a'.repeat(119))).toThrow(InvalidFormatError);
    expect(() => new PrivateKey(publicPem)).toThrow(InvalidLengthError);
    expect(PrivateKey.fromPEM(privatePem).valueOf()).toBe(privatePem);
    expect(
      PrivateKey.fromPEM(new StringValueObject(privatePem)).valueOf(),
    ).toBe(privatePem);
    expect(PrivateKey.generate()).toBeInstanceOf(PrivateKey);
  });

  it('derives the matching public key', () => {
    expect(new PrivateKey(privatePem).getPublicKey().valueOf()).toBe(publicPem);
  });

  it('signs strings, VOs and raw Media bytes', () => {
    const key = new PrivateKey(privatePem);
    const stringSig = key.sign('hello');
    const voSig = key.sign(new StringValueObject('hello'));
    const bytes = Buffer.from([0xff, 0xfe, 0xfd, 0, 0x80]);
    const mediaSig = key.sign(new Media(bytes));

    expect(stringSig).toBeInstanceOf(Signature);
    expect(stringSig.valueOf()).toHaveLength(88);
    expect(voSig).toBeInstanceOf(Signature);
    expect(
      crypto.verify(
        null,
        bytes,
        publicPem,
        Buffer.from(mediaSig.valueOf(), 'base64'),
      ),
    ).toBeTrue();
    expect(key.sign('payload-1').isEqual(key.sign('payload-2'))).toBeFalse();
  });

  it('decrypts current and empty asymmetric payloads', () => {
    const pub = new PublicKey(publicPem);
    const priv = new PrivateKey(privatePem);

    expect(priv.decrypt(pub.encrypt('secret message')).toString()).toBe(
      'secret message',
    );
    expect(priv.decrypt(pub.encrypt(''))).toHaveLength(0);
    expect(
      priv.decrypt(pub.encrypt(new StringValueObject('vo-payload'))).toString(),
    ).toBe('vo-payload');
  });

  it('decrypts legacy asymmetric payloads', () => {
    const priv = new PrivateKey(privatePem);
    const message = Buffer.from('legacy secret');
    const recipientPub = CryptoAdapter.publicKeyToX25519(publicPem);
    const ephemeralPriv = CryptoAdapter.x25519RandomPrivateKey();
    const ephemeralPub = CryptoAdapter.x25519PublicKey(ephemeralPriv);
    const sharedSecret = CryptoAdapter.x25519SharedSecret(
      ephemeralPriv,
      recipientPub,
    );
    const aesKey = CryptoAdapter.deriveEncryptionKey(sharedSecret, ephemeralPub);
    const iv = CryptoAdapter.randomBytes(12);
    const { cipherText, tag } = CryptoAdapter.encryptAes256Gcm(
      aesKey,
      iv,
      message,
    );
    const payload = new EncryptedPayload(
      [
        Buffer.from(ephemeralPub).toString('base64'),
        iv.toString('base64'),
        Buffer.from(cipherText).toString('base64'),
        Buffer.from(tag).toString('base64'),
      ].join('.'),
    );

    expect(priv.decrypt(payload).toString()).toBe('legacy secret');
  });

  it('rejects wrong keys and tampered current payload fields', () => {
    const pub = new PublicKey(publicPem);
    const priv = new PrivateKey(privatePem);
    const encrypted = pub.encrypt('secret');
    const other = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });

    expect(() => new PrivateKey(other.privateKey).decrypt(encrypted)).toThrow();

    for (const [index, value] of [
      [2, Buffer.alloc(32, 1).toString('base64')],
      [3, Buffer.alloc(12, 1).toString('base64')],
      [4, Buffer.from('tampered').toString('base64')],
      [5, Buffer.alloc(16, 1).toString('base64')],
    ] as Array<[number, string]>) {
      const parts = encrypted.valueOf().split('.');
      parts[index] = value;
      expect(() => priv.decrypt(new EncryptedPayload(parts.join('.')))).toThrow();
    }
  });

  it('validates malformed formats and algorithms', () => {
    const priv = new PrivateKey(privatePem);
    expect(() => priv.decrypt(new EncryptedPayload('only-one-field'))).toThrow(
      InvalidFormatError,
    );
    expect(() =>
      priv.decrypt(
        new EncryptedPayload(
          [
            'v2',
            'wrong-algorithm',
            Buffer.alloc(32).toString('base64'),
            Buffer.alloc(12).toString('base64'),
            '',
            Buffer.alloc(16).toString('base64'),
          ].join('.'),
        ),
      ),
    ).toThrow(InvalidFormatError);
    expect(() =>
      priv.decrypt(new EncryptedPayload('YQ==.YQ==.YQ==.YQ==')),
    ).toThrow(InvalidFormatError);
  });

  it('validates fixed field lengths before decoding', () => {
    const priv = new PrivateKey(privatePem);
    const oversized = Buffer.alloc(1024 * 1024).toString('base64');
    const payload = new EncryptedPayload(
      `${oversized}.${Buffer.alloc(12).toString('base64')}..${Buffer.alloc(16).toString('base64')}`,
    );
    const spy = jest.spyOn(Buffer, 'from');

    expect(() => priv.decrypt(payload)).toThrow(InvalidFormatError);
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('rejects oversized ciphertext before decoding', () => {
    const priv = new PrivateKey(privatePem);
    const oversized = 'A'.repeat(Math.ceil((1024 * 1024 + 1) / 3) * 4);
    expect(() =>
      priv.decrypt(
        new EncryptedPayload(
          `${Buffer.alloc(32).toString('base64')}.${Buffer.alloc(12).toString('base64')}.${oversized}.${Buffer.alloc(16).toString('base64')}`,
        ),
      ),
    ).toThrow(InvalidLengthError);
  });

  it('keeps Key and ValueObject behavior', () => {
    const first = new PrivateKey(privatePem);
    const second = new PrivateKey(privatePem);
    const cloned = (first as any).clone();
    const other = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });

    expect(first).toBeInstanceOf(Key);
    expect(first.isEqual(second)).toBeTrue();
    expect(first.isEqual(privatePem)).toBeTrue();
    expect(first.isEqual(new PrivateKey(other.privateKey))).toBeFalse();
    expect(cloned).toBeInstanceOf(PrivateKey);
    expect(cloned.valueOf()).toBe(privatePem);
  });
});
