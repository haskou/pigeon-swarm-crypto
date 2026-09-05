import * as crypto from 'node:crypto';

import { CryptoDerivation } from '../../src/internal/CryptoDerivation';

describe('CryptoDerivation', () => {
  it('derives PBKDF2 with sha256 and sha512 fallbacks', async () => {
    const salt = crypto.randomBytes(16);

    expect(
      await CryptoDerivation.pbkdf2Async(
        'secure-password',
        salt,
        100000,
        32,
        'sha256',
      ),
    ).toHaveLength(32);
    expect(
      await CryptoDerivation.pbkdf2Async(
        'secure-password',
        salt,
        100000,
        32,
        'sha512',
        {},
      ),
    ).toHaveLength(32);
  });

  it('uses an injected PBKDF2 implementation and propagates errors', async () => {
    const salt = Buffer.alloc(16, 1);
    const expected = Buffer.alloc(32, 2);
    const success = {
      pbkdf2: jest.fn((password, saltArg, iterations, keyLength, algorithm, cb) => {
        expect(password).toBe('secure-password');
        expect(saltArg).toEqual(salt);
        expect(iterations).toBe(100000);
        expect(keyLength).toBe(32);
        expect(algorithm).toBe('sha256');
        cb(null, expected);
      }),
    };
    const failure = {
      pbkdf2: jest.fn((_p, _s, _i, _k, _a, cb) =>
        cb(new Error('Mock pbkdf2 error'), Buffer.alloc(0)),
      ),
    };

    expect(
      await CryptoDerivation.pbkdf2Async(
        'secure-password',
        salt,
        100000,
        32,
        'sha256',
        success,
      ),
    ).toBe(expected);
    await expect(
      CryptoDerivation.pbkdf2Async(
        'secure-password',
        salt,
        100000,
        32,
        'sha256',
        failure,
      ),
    ).rejects.toThrow('Mock pbkdf2 error');
  });

  it('derives scrypt with fallback and injected implementations', async () => {
    const salt = Buffer.alloc(16, 3);
    expect(
      await CryptoDerivation.scryptAsync('secure-password', salt, 32, {
        N: 16,
        r: 1,
        p: 1,
      }),
    ).toHaveLength(32);

    const expected = Buffer.alloc(32, 4);
    const success = {
      scrypt: jest.fn((password, saltArg, keylen, options, cb) => {
        expect(password).toBe('secure-password');
        expect(saltArg).toEqual(salt);
        expect(keylen).toBe(32);
        expect(options).toEqual({ N: 16, r: 1, p: 1 });
        cb(null, expected);
      }),
    };
    expect(
      await CryptoDerivation.scryptAsync(
        'secure-password',
        salt,
        32,
        { N: 16, r: 1, p: 1 },
        success,
      ),
    ).toBe(expected);

    const failure = {
      scrypt: jest.fn((_p, _s, _k, _o, cb) =>
        cb(new Error('Mock scrypt error'), Buffer.alloc(0)),
      ),
    };
    await expect(
      CryptoDerivation.scryptAsync(
        'secure-password',
        salt,
        32,
        { N: 16, r: 1, p: 1 },
        failure,
      ),
    ).rejects.toThrow('Mock scrypt error');
  });

  it('generates random bytes with fallback and injected implementations', async () => {
    expect(await CryptoDerivation.randomBytesAsync(16)).toHaveLength(16);

    const expected = Buffer.alloc(16, 5);
    const success = {
      randomBytes: jest.fn((size, cb) => {
        expect(size).toBe(16);
        cb(null, expected);
      }),
    };
    expect(await CryptoDerivation.randomBytesAsync(16, success)).toEqual(
      expected,
    );

    const failure = {
      randomBytes: jest.fn((_size, cb) =>
        cb(new Error('Mock randomBytes error'), Buffer.alloc(0)),
      ),
    };
    await expect(CryptoDerivation.randomBytesAsync(16, failure)).rejects.toThrow(
      'Mock randomBytes error',
    );
  });
});
