import { StringValueObject } from '@haskou/value-objects';

import {
  EncryptedKeyPair,
  EncryptedPayload,
  EncryptedPrivateKey,
  KeyPair,
  PublicKey,
  Signature,
} from '../../src';

describe('EncryptedKeyPair', () => {
  let keyPair: KeyPair;
  const password = 'encryption-password';

  beforeAll(async () => {
    keyPair = await KeyPair.generate();
  });

  it('constructs from public and encrypted private keys', () => {
    const pair = new EncryptedKeyPair(
      new PublicKey(keyPair.toPrimitives().publicKey),
      new EncryptedPrivateKey('enc.priv.key.tag'),
    );
    expect(pair).toBeInstanceOf(EncryptedKeyPair);
  });

  it('encrypts key pairs with string and VO passwords', async () => {
    const encrypted = await keyPair.encryptKeyPair(password);
    const encryptedVo = await keyPair.encryptKeyPair(
      new StringValueObject(password),
    );

    expect(encrypted).toBeInstanceOf(EncryptedKeyPair);
    expect(encryptedVo).toBeInstanceOf(EncryptedKeyPair);
    expect(encrypted.toPrimitives().publicKey).toBe(
      keyPair.toPrimitives().publicKey,
    );
    expect(encrypted.toPrimitives().encryptedPrivateKey.split('.')).toHaveLength(
      9,
    );
  });

  it('round-trips primitives and remains functional', async () => {
    const encrypted = await keyPair.encryptKeyPair(password);
    const primitives = encrypted.toPrimitives();
    const recreated = EncryptedKeyPair.fromPrimitives(primitives);
    const signature = await recreated.sign('verify', password);

    expect(recreated.toPrimitives()).toEqual(primitives);
    expect(recreated.isValidSignature('verify', signature)).toBeTrue();
  });

  it('signs and verifies with string and VO passwords', async () => {
    const encrypted = await keyPair.encryptKeyPair(password);
    const first = await encrypted.sign('hello', password);
    const second = await encrypted.sign(
      'data',
      new StringValueObject(password),
    );

    expect(first).toBeInstanceOf(Signature);
    expect(second).toBeInstanceOf(Signature);
    expect(encrypted.isValidSignature('hello', first)).toBeTrue();
    expect(encrypted.isValidSignature('tampered', first)).toBeFalse();
    expect(encrypted.isValidSignature('cross', keyPair.sign('cross'))).toBeTrue();

    const other = await KeyPair.generate();
    expect(encrypted.isValidSignature('hello', other.sign('hello'))).toBeFalse();
  });

  it('encrypts and decrypts payloads', async () => {
    const encryptedPair = await keyPair.encryptKeyPair(password);
    const cipher = encryptedPair.encrypt('round-trip encrypted');
    const voCipher = encryptedPair.encrypt(new StringValueObject('vo-secret'));

    expect(cipher).toBeInstanceOf(EncryptedPayload);
    expect(voCipher).toBeInstanceOf(EncryptedPayload);
    expect((await encryptedPair.decrypt(cipher, password)).toString()).toBe(
      'round-trip encrypted',
    );
    expect(
      (
        await encryptedPair.decrypt(
          voCipher,
          new StringValueObject(password),
        )
      ).toString(),
    ).toBe('vo-secret');
    await expect(encryptedPair.decrypt(cipher, 'wrong-password')).toReject();
  });
});
