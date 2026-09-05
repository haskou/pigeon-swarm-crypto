import {
  EncryptedPrivateKey,
  EncryptedPayload,
  KeyPair,
  MD5Hash,
  PrivateKey,
  PublicKey,
  SHA256Hash,
  SHA512Hash,
  Signature,
  SymmetricKey,
} from '../src';

describe('crypto migration contract', () => {
  it('exports the legacy crypto API from the dedicated package', () => {
    expect(KeyPair).toBeDefined();
    expect(PrivateKey).toBeDefined();
    expect(PublicKey).toBeDefined();
    expect(SymmetricKey).toBeDefined();
    expect(EncryptedPrivateKey).toBeDefined();
    expect(EncryptedPayload).toBeDefined();
    expect(Signature).toBeDefined();
  });

  it('signs, verifies, encrypts and decrypts with a generated key pair', async () => {
    const keyPair = await KeyPair.generate();
    const signature = keyPair.sign('message');
    const encrypted = keyPair.encrypt('secret');

    expect(keyPair.isValidSignature('message', signature)).toBeTrue();
    expect(keyPair.decrypt(encrypted).toString()).toBe('secret');
  });

  it('encrypts and decrypts with a symmetric key', () => {
    const key = SymmetricKey.generate();
    const encrypted = key.encrypt('secret');

    expect(key.decrypt(encrypted).toString()).toBe('secret');
  });

  it('keeps digest computation in the crypto package', () => {
    expect(MD5Hash.from('hello').valueOf()).toBe(
      '5d41402abc4b2a76b9719d911017c592',
    );
    expect(SHA256Hash.from('hello').valueOf()).toHaveLength(64);
    expect(SHA512Hash.from('hello').valueOf()).toHaveLength(128);
  });
});
