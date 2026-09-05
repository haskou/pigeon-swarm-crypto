import {
  InvalidFormatError,
  InvalidLengthError,
  Media,
  NullObject,
  Password,
  StringValueObject,
} from '@haskou/value-objects';

import {
  EncryptedPayload,
  SymmetricEncryptedPayload,
  SymmetricKey,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import { CryptoDerivation } from '../../src/internal/CryptoDerivation';

describe('SymmetricKey', () => {
  const keyBytes = Buffer.alloc(32, 7);
  const keyBase64 = keyBytes.toString('base64');

  it('validates construction and factories', () => {
    expect(
      NullObject.isNullObject(new SymmetricKey(undefined as unknown as string)),
    ).toBeTrue();
    expect(
      NullObject.isNullObject(new SymmetricKey(null as unknown as string)),
    ).toBeTrue();
    expect(new SymmetricKey(keyBase64).getBuffer()).toEqual(keyBytes);
    expect(() => new SymmetricKey('*'.repeat(44))).toThrow(InvalidFormatError);
    expect(() => new SymmetricKey(Buffer.alloc(31).toString('base64'))).toThrow(
      InvalidLengthError,
    );
    expect(SymmetricKey.fromBase64(keyBase64).getBuffer()).toEqual(keyBytes);
    expect(
      SymmetricKey.fromBase64(new StringValueObject(keyBase64)).getBuffer(),
    ).toEqual(keyBytes);
    expect(SymmetricKey.fromBuffer(keyBytes).valueOf()).toBe(keyBase64);
    expect(() => SymmetricKey.fromBuffer(Buffer.alloc(33))).toThrow(
      InvalidLengthError,
    );
    expect(SymmetricKey.generate().getBuffer()).toHaveLength(32);
  });

  it('derives deterministic and salted password keys', async () => {
    const first = await SymmetricKey.fromPassword('password', {
      salt: 'stable-salt',
    });
    const second = await SymmetricKey.fromPassword('password', {
      salt: 'stable-salt',
    });
    const otherSalt = await SymmetricKey.fromPassword('password', {
      salt: 'other-salt',
    });
    const custom = await SymmetricKey.fromPassword(
      new StringValueObject('password'),
      { N: 16, p: 1, r: 1, salt: Buffer.from('buffer-salt') },
    );

    expect(first.isEqual(second)).toBeTrue();
    expect(first.isEqual(otherSalt)).toBeFalse();
    expect(custom.getBuffer()).toHaveLength(32);
  });

  it('uses legacy and OWASP scrypt defaults', async () => {
    const spy = jest
      .spyOn(CryptoDerivation, 'scryptAsync')
      .mockResolvedValue(Buffer.alloc(32, 9));

    await SymmetricKey.fromPassword('password', { salt: 'stable-salt' });
    expect(spy).toHaveBeenLastCalledWith(
      'password',
      Buffer.from('stable-salt'),
      32,
      { N: 16384, p: 1, r: 8 },
    );

    await SymmetricKey.fromPasswordUsingOwasp(
      new Password('Secure-password-123!'),
      { salt: 'stable-salt' },
    );
    expect(spy).toHaveBeenLastCalledWith(
      'Secure-password-123!',
      Buffer.from('stable-salt'),
      32,
      { N: 16384, p: 5, r: 8 },
    );
    spy.mockRestore();

    await expect(
      SymmetricKey.fromPassword('password', { salt: '' }),
    ).rejects.toThrow(InvalidLengthError);
  });

  it('encrypts strings, VOs, buffers, Media and empty payloads', () => {
    const key = new SymmetricKey(keyBase64);
    const first = key.encrypt('same payload');
    const second = key.encrypt('same payload');
    const vo = key.encrypt(new StringValueObject('vo-payload'));
    const buffer = Buffer.from([0, 1, 2, 255]);
    const mediaBytes = Buffer.from([0xff, 0xfe, 0xfd, 0, 0x80]);
    const media = key.encrypt(new Media(mediaBytes));
    const empty = key.encrypt('');

    expect(first).toBeInstanceOf(SymmetricEncryptedPayload);
    expect(first).toBeInstanceOf(EncryptedPayload);
    expect(first.getScheme()).toBe('symmetric');
    expect(first.isEqual(second)).toBeFalse();
    expect(key.decrypt(first).toString()).toBe('same payload');
    expect(key.decrypt(vo).toString()).toBe('vo-payload');
    expect(key.decrypt(key.encrypt(buffer))).toEqual(buffer);
    expect(key.decrypt(media)).toEqual(mediaBytes);
    expect(key.decrypt(empty)).toHaveLength(0);
  });

  it('supports payloads above asymmetric limit and enforces symmetric limit', () => {
    const key = new SymmetricKey(keyBase64);
    const large = Buffer.alloc(1024 * 1024 + 1, 7);
    expect(key.decrypt(key.encrypt(large))).toEqual(large);
    expect(() => key.encrypt(Buffer.alloc(8 * 1024 * 1024 + 1))).toThrow(
      InvalidLengthError,
    );
  });

  it('rejects wrong keys and tampered fields', () => {
    const key = new SymmetricKey(keyBase64);
    const encrypted = key.encrypt('secret');
    expect(() =>
      SymmetricKey.fromBuffer(Buffer.alloc(32, 8)).decrypt(encrypted),
    ).toThrow();

    for (const [index, value] of [
      [2, Buffer.alloc(12, 1).toString('base64')],
      [3, Buffer.from('tampered').toString('base64')],
      [4, Buffer.alloc(16, 1).toString('base64')],
    ] as Array<[number, string]>) {
      const parts = encrypted.valueOf().split('.');
      parts[index] = value;
      expect(() =>
        key.decrypt(new SymmetricEncryptedPayload(parts.join('.'))),
      ).toThrow();
    }
  });

  it('authenticates string and Buffer AAD', () => {
    const key = new SymmetricKey(keyBase64);
    const stringAad = key.encrypt('secret', { aad: 'domain.header' });
    expect(key.decrypt(stringAad, { aad: 'domain.header' }).toString()).toBe(
      'secret',
    );
    expect(() => key.decrypt(stringAad, { aad: 'other.header' })).toThrow();

    const bufferAad = Buffer.from('domain.header');
    const encrypted = key.encrypt('secret', { aad: bufferAad });
    expect(key.decrypt(encrypted, { aad: bufferAad }).toString()).toBe('secret');
  });

  it('decrypts legacy symmetric payloads without AAD', () => {
    const key = new SymmetricKey(keyBase64);
    const iv = Buffer.alloc(12, 2);
    const { cipherText, tag } = CryptoAdapter.encryptAes256Gcm(
      key.getBuffer(),
      iv,
      Buffer.from('legacy secret'),
    );
    const payload = new SymmetricEncryptedPayload(
      [
        'v1',
        'aes-256-gcm',
        iv.toString('base64'),
        Buffer.from(cipherText).toString('base64'),
        Buffer.from(tag).toString('base64'),
      ].join('.'),
    );
    expect(key.decrypt(payload).toString()).toBe('legacy secret');
  });

  it('validates encrypted payload structure and field lengths', () => {
    const key = new SymmetricKey(keyBase64);
    const validIv = Buffer.alloc(12).toString('base64');
    const validTag = Buffer.alloc(16).toString('base64');

    expect(() => key.decrypt(new EncryptedPayload('v1.aes-256-gcm.iv'))).toThrow(
      InvalidFormatError,
    );
    expect(() =>
      key.decrypt(
        new EncryptedPayload(
          ['v2', 'aes-256-gcm', validIv, '', validTag].join('.'),
        ),
      ),
    ).toThrow(InvalidFormatError);
    expect(() =>
      key.decrypt(
        new EncryptedPayload(
          ['v1', 'aes-256-gcm', '*', '', validTag].join('.'),
        ),
      ),
    ).toThrow(InvalidFormatError);
    expect(() =>
      key.decrypt(
        new EncryptedPayload(
          [
            'v1',
            'aes-256-gcm',
            Buffer.alloc(11).toString('base64'),
            '',
            validTag,
          ].join('.'),
        ),
      ),
    ).toThrow(InvalidFormatError);
    expect(() =>
      key.decrypt(
        new EncryptedPayload(
          ['v1', 'aes-256-gcm', validIv, '*', validTag].join('.'),
        ),
      ),
    ).toThrow(InvalidFormatError);
    expect(() =>
      key.decrypt(
        new EncryptedPayload(
          [
            'v1',
            'aes-256-gcm',
            validIv,
            '',
            Buffer.alloc(15).toString('base64'),
          ].join('.'),
        ),
      ),
    ).toThrow(InvalidFormatError);

    const oversized = 'A'.repeat(Math.ceil((8 * 1024 * 1024 + 1) / 3) * 4);
    expect(() =>
      key.decrypt(
        new EncryptedPayload(
          ['v1', 'aes-256-gcm', validIv, oversized, validTag].join('.'),
        ),
      ),
    ).toThrow(InvalidLengthError);
  });
});
