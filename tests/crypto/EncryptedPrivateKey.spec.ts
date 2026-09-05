import { NullObject, Password, StringValueObject } from '@haskou/value-objects';
import * as crypto from 'node:crypto';

import {
  EncryptedPrivateKey,
  InvalidEncryptedPrivateKeyFormatError,
  PrivateKey,
  SymmetricEncryptedPayload,
  SymmetricKey,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import { CryptoDerivation } from '../../src/internal/CryptoDerivation';
import { EncryptedPrivateKeyV2 } from '../../src/internal/EncryptedPrivateKeyV2';
import { EncryptedPrivateKeyV3 } from '../../src/internal/EncryptedPrivateKeyV3';

describe('EncryptedPrivateKey', () => {
  let privatePem: string;
  let publicPem: string;
  const password = new Password('Secure-password-123!');

  beforeAll(() => {
    const pair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    privatePem = pair.privateKey;
    publicPem = pair.publicKey;
  });

  it('handles construction and StringValueObject input', () => {
    expect(
      NullObject.isNullObject(
        new EncryptedPrivateKey(undefined as unknown as string),
      ),
    ).toBeTrue();
    expect(
      NullObject.isNullObject(new EncryptedPrivateKey(null as unknown as string)),
    ).toBeTrue();
    expect(new EncryptedPrivateKey('encrypted.iv.salt.tag').valueOf()).toBe(
      'encrypted.iv.salt.tag',
    );
    expect(
      new EncryptedPrivateKey(
        new StringValueObject('encrypted.iv.salt.tag'),
      ).valueOf(),
    ).toBe('encrypted.iv.salt.tag');
  });

  it('creates v3 private-key ciphertext with random salt and IV', async () => {
    const privateKey = new PrivateKey(privatePem);
    const first = await EncryptedPrivateKey.create(privateKey, password);
    const second = await EncryptedPrivateKey.create(privateKey, password);
    const parts = first.valueOf().split('.');

    expect(first).toBeInstanceOf(EncryptedPrivateKey);
    expect(parts).toHaveLength(9);
    expect(parts.slice(0, 5)).toEqual(['v3', 'scrypt', 'N16384', 'r8', 'p5']);
    expect(first.isEqual(second)).toBeFalse();
    expect(
      await EncryptedPrivateKey.create(
        privateKey,
        new StringValueObject(password),
      ),
    ).toBeInstanceOf(EncryptedPrivateKey);
  });

  it('decrypts current format and rejects wrong passwords or formats', async () => {
    const encrypted = await EncryptedPrivateKey.create(
      new PrivateKey(privatePem),
      password,
    );
    expect((await encrypted.decrypt(password)).valueOf()).toBe(privatePem);
    await expect(encrypted.decrypt('wrong-password')).toReject();
    await expect(
      new EncryptedPrivateKey('invalid.format').decrypt(password),
    ).rejects.toThrow(InvalidEncryptedPrivateKeyFormatError);
  });

  it('rejects unsupported or malformed KDF parameters before scrypt', async () => {
    const encrypted = await EncryptedPrivateKey.create(
      new PrivateKey(privatePem),
      password,
    );
    for (const value of ['N1073741824', 'N16384junk']) {
      const parts = encrypted.valueOf().split('.');
      parts[2] = value;
      const spy = jest.spyOn(CryptoDerivation, 'scryptAsync');
      await expect(
        new EncryptedPrivateKey(parts.join('.')).decrypt(password),
      ).rejects.toThrow(InvalidEncryptedPrivateKeyFormatError);
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    }
  });

  it('preserves v2 format and reports it as needing re-encryption', async () => {
    const privateKey = new PrivateKey(privatePem);
    const v2 = await EncryptedPrivateKeyV2.encrypt(privateKey, password);
    const parts = v2.split('.');
    const key = await SymmetricKey.fromPassword(password, {
      N: 16384,
      p: 1,
      r: 8,
      salt: Buffer.from(parts[5], 'base64'),
    });
    const payload = new SymmetricEncryptedPayload(
      ['v1', 'aes-256-gcm', parts[6], parts[8], parts[7]].join('.'),
    );

    expect(key.decrypt(payload).toString()).toBe(privatePem);
    expect((await new EncryptedPrivateKey(v2).decrypt(password)).valueOf()).toBe(
      privatePem,
    );
    expect(new EncryptedPrivateKey(v2).needsReEncryption()).toBeTrue();

    parts[4] = 'p2';
    await expect(
      new EncryptedPrivateKeyV2().decrypt(parts, password),
    ).rejects.toThrow(InvalidEncryptedPrivateKeyFormatError);
  });

  it('decrypts old v2 payloads created without AAD', async () => {
    const salt = Buffer.alloc(16, 3);
    const iv = Buffer.alloc(12, 4);
    const key = await SymmetricKey.fromPassword(password, {
      N: 16384,
      p: 1,
      r: 8,
      salt,
    });
    const { cipherText, tag } = CryptoAdapter.encryptAes256Gcm(
      key.getBuffer(),
      iv,
      Buffer.from(privatePem),
    );
    const encrypted = [
      'v2',
      'scrypt',
      'N16384',
      'r8',
      'p1',
      salt.toString('base64'),
      iv.toString('base64'),
      Buffer.from(tag).toString('base64'),
      Buffer.from(cipherText).toString('base64'),
    ].join('.');

    expect((await new EncryptedPrivateKey(encrypted).decrypt(password)).valueOf()).toBe(
      privatePem,
    );
  });

  it('keeps v3 fields compatible with SymmetricKey and authenticates AAD', async () => {
    const encrypted = await EncryptedPrivateKey.create(
      new PrivateKey(privatePem),
      password,
    );
    const parts = encrypted.valueOf().split('.');
    const key = await SymmetricKey.fromPassword(password, {
      N: 16384,
      p: 5,
      r: 8,
      salt: Buffer.from(parts[5], 'base64'),
    });
    const payload = new SymmetricEncryptedPayload(
      ['v1', 'aes-256-gcm', parts[6], parts[8], parts[7]].join('.'),
    );

    expect(
      key.decrypt(payload, { aad: parts.slice(0, 5).join('.') }).toString(),
    ).toBe(privatePem);

    const tampered = [...parts];
    tampered[1] = 'tampered-kdf';
    await expect(
      new EncryptedPrivateKeyV3().decrypt(tampered, password),
    ).toReject();
  });

  it('rejects unsupported v3 params and invalid salts before scrypt', async () => {
    const encrypted = await EncryptedPrivateKey.create(
      new PrivateKey(privatePem),
      password,
    );

    const unsupported = encrypted.valueOf().split('.');
    unsupported[4] = 'p1';
    await expect(
      new EncryptedPrivateKeyV3().decrypt(unsupported, password),
    ).rejects.toThrow(InvalidEncryptedPrivateKeyFormatError);

    for (const invalidSalt of [
      'not-base64!',
      Buffer.alloc(15).toString('base64'),
    ]) {
      const parts = encrypted.valueOf().split('.');
      parts[5] = invalidSalt;
      const spy = jest.spyOn(CryptoDerivation, 'scryptAsync');
      await expect(
        new EncryptedPrivateKeyV3().decrypt(parts, password),
      ).rejects.toThrow(InvalidEncryptedPrivateKeyFormatError);
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    }
  });

  it('decrypts legacy PBKDF2 private-key format', async () => {
    const salt = crypto.randomBytes(16);
    const iv = crypto.randomBytes(12);
    const key = await new Promise<Buffer>((resolve, reject) => {
      crypto.pbkdf2(
        password.valueOf(),
        salt,
        100000,
        32,
        'sha256',
        (error, derived) => (error ? reject(error) : resolve(derived)),
      );
    });
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encryptedData = Buffer.concat([
      cipher.update(privatePem),
      cipher.final(),
    ]);
    const legacy = [
      encryptedData.toString('base64'),
      iv.toString('base64'),
      salt.toString('base64'),
      cipher.getAuthTag().toString('base64'),
    ].join('.');

    expect((await new EncryptedPrivateKey(legacy).decrypt(password)).valueOf()).toBe(
      privatePem,
    );
    expect(new EncryptedPrivateKey(legacy).needsReEncryption()).toBeTrue();
  });

  it('returns correct re-encryption state and produces functional decrypted keys', async () => {
    const encrypted = await EncryptedPrivateKey.create(
      new PrivateKey(privatePem),
      password,
    );
    const decrypted = await encrypted.decrypt(new StringValueObject(password));
    const signature = decrypted.sign('test payload');

    expect(encrypted.needsReEncryption()).toBeFalse();
    expect(new EncryptedPrivateKey('invalid.format').needsReEncryption()).toBeFalse();
    expect(
      crypto.verify(
        null,
        Buffer.from('test payload'),
        publicPem,
        Buffer.from(signature.valueOf(), 'base64'),
      ),
    ).toBeTrue();
  });

  it('keeps ValueObject equality and cloning', () => {
    const first = new EncryptedPrivateKey('same-encrypted');
    const second = new EncryptedPrivateKey('same-encrypted');
    const different = new EncryptedPrivateKey('different-encrypted');
    const cloned = (first as any).clone();

    expect(first.isEqual(second)).toBeTrue();
    expect(first.isEqual(different)).toBeFalse();
    expect(cloned).toBeInstanceOf(EncryptedPrivateKey);
    expect(cloned.valueOf()).toBe(first.valueOf());
    expect(cloned).not.toBe(first);
  });
});
