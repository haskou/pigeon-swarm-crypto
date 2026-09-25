import { NullObject, Password } from '@haskou/value-objects';

import {
  InvalidProtectedUserRootKeyError,
  ProtectedUserRootKey,
  UserRootKey,
  UserRootKeySecondFactor,
} from '../../src';
import { CryptoDerivation } from '../../src/internal/CryptoDerivation';

jest.setTimeout(30_000);

describe('UserRootKey', () => {
  const password = new Password('Correct-horse-battery-staple-7!');
  const nextPassword = new Password('Different-long-password-9!');

  it('protects a random root key with both password and second factor', async () => {
    const rootKey = UserRootKey.generate();
    const factor = UserRootKeySecondFactor.generate();
    const first = await ProtectedUserRootKey.create(rootKey, password, factor);
    const second = await ProtectedUserRootKey.create(rootKey, password, factor);

    expect(first.valueOf().split('.').slice(0, 7)).toEqual([
      'v1',
      'scrypt',
      'N262144',
      'r8',
      'p1',
      'hkdf-sha256',
      'aes-256-gcm',
    ]);
    expect(first.isEqual(second)).toBeFalse();
    expect((await first.unlock(password, factor)).isEqual(rootKey)).toBeTrue();
  });

  it('requires both factors and fails with one wrong factor', async () => {
    const factor = UserRootKeySecondFactor.generate();
    const protectedKey = await ProtectedUserRootKey.create(
      UserRootKey.generate(),
      password,
      factor,
    );

    await expect(
      protectedKey.unlock(password, UserRootKeySecondFactor.generate()),
    ).rejects.toThrow(InvalidProtectedUserRootKeyError);
    await expect(
      protectedKey.unlock('wrong password', factor),
    ).rejects.toThrow(InvalidProtectedUserRootKeyError);
  });

  it('rewraps the same root key without preserving old unlock access', async () => {
    const rootKey = UserRootKey.generate();
    const oldFactor = UserRootKeySecondFactor.generate();
    const nextFactor = UserRootKeySecondFactor.generate();
    const initial = await ProtectedUserRootKey.create(
      rootKey,
      password,
      oldFactor,
    );
    const rotated = await initial.rewrap(
      password,
      oldFactor,
      nextPassword,
      nextFactor,
    );

    expect(
      (await rotated.unlock(nextPassword, nextFactor)).isEqual(rootKey),
    ).toBeTrue();
    await expect(rotated.unlock(password, oldFactor)).rejects.toThrow(
      InvalidProtectedUserRootKeyError,
    );
  });

  it('rejects malformed and tampered envelopes without exposing secrets', async () => {
    const rootKey = UserRootKey.generate();
    const factor = UserRootKeySecondFactor.generate();
    const protectedKey = await ProtectedUserRootKey.create(
      rootKey,
      password,
      factor,
    );
    const values = protectedKey.valueOf().split('.');
    values[2] = 'N1073741824';

    for (const candidate of [
      'invalid',
      values.join('.'),
      `${protectedKey.valueOf()}leak`,
    ]) {
      const malformed = new ProtectedUserRootKey(candidate);
      try {
        await malformed.unlock(password, factor);
        throw new Error('Expected unlock to fail');
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidProtectedUserRootKeyError);
        expect(String(error)).not.toContain(password.valueOf());
        expect(String(error)).not.toContain(rootKey.valueOf());
        expect(String(error)).not.toContain(factor.valueOf());
        expect(String(error)).not.toContain(candidate);
      }
    }
  });

  it('validates canonical 32-byte root keys and second factors', () => {
    const rootKey = UserRootKey.generate();
    const factor = UserRootKeySecondFactor.generate();
    const factorBytes = Buffer.alloc(32, 5);

    expect(UserRootKey.fromBase64(rootKey.valueOf()).isEqual(rootKey)).toBeTrue();
    expect(
      UserRootKeySecondFactor.fromBase64(factor.valueOf()).isEqual(factor),
    ).toBeTrue();
    expect(
      UserRootKeySecondFactor.fromBuffer(factorBytes).valueOf(),
    ).toBe(factorBytes.toString('base64'));
    expect(factorBytes).toEqual(Buffer.alloc(32, 5));
    expect(() => UserRootKey.fromBase64(Buffer.alloc(31).toString('base64'))).toThrow();
    expect(() =>
      UserRootKeySecondFactor.fromBase64(Buffer.alloc(33).toString('base64')),
    ).toThrow();
    const nonCanonical = `${'A'.repeat(42)}B=`;
    expect(() => UserRootKey.fromBase64(nonCanonical)).toThrow();
    expect(() => UserRootKeySecondFactor.fromBase64(nonCanonical)).toThrow();
    expect(
      NullObject.isNullObject(
        new UserRootKey(undefined as unknown as string),
      ),
    ).toBeTrue();
    expect(
      NullObject.isNullObject(
        new UserRootKeySecondFactor(undefined as unknown as string),
      ),
    ).toBeTrue();
  });

  it('rejects oversized envelopes before deriving a password key', async () => {
    const factor = UserRootKeySecondFactor.generate();

    await expect(
      new ProtectedUserRootKey('x'.repeat(513)).unlock(password, factor),
    ).rejects.toThrow(InvalidProtectedUserRootKeyError);
  });

  it('rejects a null root key before deriving protection material', async () => {
    const derive = jest.spyOn(CryptoDerivation, 'scryptAsync');

    await expect(
      ProtectedUserRootKey.create(
        new UserRootKey(undefined as unknown as string),
        password,
        UserRootKeySecondFactor.generate(),
      ),
    ).rejects.toThrow(InvalidProtectedUserRootKeyError);
    expect(derive).not.toHaveBeenCalled();
    derive.mockRestore();
  });

  it('clears password-derived bytes when second-factor access fails', async () => {
    const factor = UserRootKeySecondFactor.generate();
    const protectedKey = await ProtectedUserRootKey.create(
      UserRootKey.generate(),
      password,
      factor,
    );
    const derived = Buffer.alloc(32, 7);
    const derive = jest
      .spyOn(CryptoDerivation, 'scryptAsync')
      .mockResolvedValue(derived);

    await expect(
      protectedKey.unlock(
        password,
        new UserRootKeySecondFactor(undefined as unknown as string),
      ),
    ).rejects.toThrow(InvalidProtectedUserRootKeyError);
    expect(derived).toEqual(Buffer.alloc(32));
    derive.mockRestore();
  });
});
