import { Media, StringValueObject } from '@haskou/value-objects';

import { MD5Hash, SHA256Hash, SHA512Hash } from '../../src';

describe('hash factories', () => {
  it('computes MD5 from strings, VOs and Media', () => {
    expect(MD5Hash.from('hello').valueOf()).toBe(
      '5d41402abc4b2a76b9719d911017c592',
    );
    expect(MD5Hash.from(new StringValueObject('hello')).valueOf()).toBe(
      '5d41402abc4b2a76b9719d911017c592',
    );
    expect(MD5Hash.from(new Media(Buffer.from('hello'))).valueOf()).toBe(
      '5d41402abc4b2a76b9719d911017c592',
    );
  });

  it('computes SHA-256 from strings and Media', () => {
    expect(SHA256Hash.from('hello').valueOf()).toBe(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    );
    expect(SHA256Hash.from(new Media(Buffer.from('hello'))).valueOf()).toBe(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    );
  });

  it('computes SHA-512 from strings and Media', () => {
    expect(SHA512Hash.from('hello').valueOf()).toHaveLength(128);
    expect(SHA512Hash.from(new Media(Buffer.from('hello'))).valueOf()).toHaveLength(
      128,
    );
  });
});
