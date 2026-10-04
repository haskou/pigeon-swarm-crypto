import { CryptoDerivation } from '../../src/internal/CryptoDerivation';

describe('CryptoDerivation', () => {
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
