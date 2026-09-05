import * as library from '../src';

describe('crypto migration contract', () => {
  it('exports the legacy crypto API from the dedicated package', () => {
    expect((library as Record<string, unknown>).KeyPair).toBeDefined();
    expect((library as Record<string, unknown>).PrivateKey).toBeDefined();
    expect((library as Record<string, unknown>).PublicKey).toBeDefined();
    expect((library as Record<string, unknown>).SymmetricKey).toBeDefined();
    expect((library as Record<string, unknown>).EncryptedPrivateKey).toBeDefined();
    expect((library as Record<string, unknown>).EncryptedPayload).toBeDefined();
    expect((library as Record<string, unknown>).Signature).toBeDefined();
  });
});
