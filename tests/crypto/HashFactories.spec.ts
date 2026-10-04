import { Media } from '@haskou/value-objects';

import { SHA256Hash, SHA512Hash } from '../../src';

describe('hash factories', () => {
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
