import { Media, SHA256Hash as DigestValue } from '@haskou/value-objects';
import type * as previousUi from 'legacy-value-objects-v2';

import {
  EncryptedPayload,
  EncryptedPrivateKey,
  KeyPair,
  PrivateKey,
  SHA256Hash,
  Signature,
  SymmetricKey,
} from '../src';

describe.each([
  ['UI 2.10.0', 'legacy-value-objects-v2'],
  ['backend 3.0.1', 'legacy-value-objects-v3'],
] as const)('wire compatibility with %s', (_name, moduleName) => {
  const previous = jest.requireActual<typeof previousUi>(moduleName);
  it('verifies signatures across package versions', async () => {
    const oldPair = await previous.KeyPair.generate();
    const pair = KeyPair.fromPrimitives(oldPair.toPrimitives());

    expect(
      pair.isValidSignature(
        'message',
        new Signature(oldPair.sign('message').valueOf()),
      ),
    ).toBe(true);
    expect(
      oldPair.isValidSignature(
        'message',
        new previous.Signature(pair.sign('message').valueOf()),
      ),
    ).toBe(true);
    expect(
      pair.isValidSignature(
        'modified',
        new Signature(oldPair.sign('message').valueOf()),
      ),
    ).toBe(false);
  });

  it('exchanges asymmetric ciphertext in both directions', async () => {
    const oldPair = await previous.KeyPair.generate();
    const pair = KeyPair.fromPrimitives(oldPair.toPrimitives());

    expect(
      pair
        .decrypt(new EncryptedPayload(oldPair.encrypt('old message').valueOf()))
        .toString(),
    ).toBe('old message');
    expect(
      oldPair
        .decrypt(
          new previous.EncryptedPayload(pair.encrypt('new message').valueOf()),
        )
        .toString(),
    ).toBe('new message');
  });

  it('exchanges symmetric ciphertext in both directions', () => {
    const oldKey = previous.SymmetricKey.generate();
    const key = SymmetricKey.fromBase64(oldKey.valueOf());

    expect(
      key
        .decrypt(new EncryptedPayload(oldKey.encrypt('old message').valueOf()))
        .toString(),
    ).toBe('old message');
    expect(
      oldKey
        .decrypt(
          new previous.EncryptedPayload(key.encrypt('new message').valueOf()),
        )
        .toString(),
    ).toBe('new message');
  });

  it('unlocks protected private keys across package versions', async () => {
    const password = 'Disposable compatibility test password';
    const oldKey = previous.PrivateKey.generate();
    const protectedOldKey = await previous.EncryptedPrivateKey.create(
      oldKey,
      password,
    );
    const key = await new EncryptedPrivateKey(
      protectedOldKey.valueOf(),
    ).decrypt(password);

    expect(key.valueOf()).toBe(oldKey.valueOf());

    const protectedNewKey = await EncryptedPrivateKey.create(
      new PrivateKey(oldKey.valueOf()),
      password,
    );
    const restored = await new previous.EncryptedPrivateKey(
      protectedNewKey.valueOf(),
    ).decrypt(password);

    expect(restored.valueOf()).toBe(oldKey.valueOf());
    await expect(
      new EncryptedPrivateKey(protectedOldKey.valueOf()).decrypt(
        'Wrong compatibility test password',
      ),
    ).rejects.toThrow();
  });
});

describe('value-objects 7 integration', () => {
  it('encrypts Media from the consumer value-object runtime', () => {
    const key = SymmetricKey.generate();
    const bytes = Buffer.from([0, 255, 1, 128]);

    expect(key.decrypt(key.encrypt(new Media(bytes)))).toEqual(bytes);
  });

  it('distinguishes digest representation from the crypto factory type', () => {
    const digest = SHA256Hash.from('message');
    const representation = new DigestValue(digest.valueOf());

    expect(digest.isEqual(SHA256Hash.from('message'))).toBe(true);
    expect(digest.isEqual(representation)).toBe(false);
    expect(digest.hasValue(representation)).toBe(true);
  });
});
