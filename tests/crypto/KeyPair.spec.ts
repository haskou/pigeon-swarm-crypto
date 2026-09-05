import { StringValueObject } from '@haskou/value-objects';

import {
  EncryptedKeyPair,
  EncryptedPayload,
  KeyPair,
  PrivateKey,
  PublicKey,
  Signature,
} from '../../src';

describe('KeyPair', () => {
  let keyPair: KeyPair;

  beforeAll(async () => {
    keyPair = await KeyPair.generate();
  });

  it('generates unique PEM key pairs', async () => {
    const first = await KeyPair.generate();
    const second = await KeyPair.generate();

    expect(first).toBeInstanceOf(KeyPair);
    expect(first.toPrimitives().publicKey).toContain('BEGIN PUBLIC KEY');
    expect(first.toPrimitives().privateKey).toContain('BEGIN PRIVATE KEY');
    expect(first.toPrimitives().publicKey).not.toBe(
      second.toPrimitives().publicKey,
    );
  });

  it('constructs and round-trips primitives', () => {
    const primitives = keyPair.toPrimitives();
    const pair = new KeyPair(
      new PublicKey(primitives.publicKey),
      new PrivateKey(primitives.privateKey),
    );
    const recreated = KeyPair.fromPrimitives(pair.toPrimitives());
    const signature = recreated.sign('payload');

    expect(recreated.toPrimitives()).toEqual(primitives);
    expect(recreated.isValidSignature('payload', signature)).toBeTrue();
  });

  it('signs string and StringValueObject payloads', () => {
    const first = keyPair.sign('hello');
    const second = keyPair.sign(new StringValueObject('data'));
    const different = keyPair.sign('other');

    expect(first).toBeInstanceOf(Signature);
    expect(second).toBeInstanceOf(Signature);
    expect(first.valueOf()).toHaveLength(88);
    expect(first.isEqual(different)).toBeFalse();
    expect(keyPair.isValidSignature('hello', first)).toBeTrue();
    expect(keyPair.isValidSignature('tampered', first)).toBeFalse();
  });

  it('rejects signatures from another pair', async () => {
    const other = await KeyPair.generate();
    expect(keyPair.isValidSignature('message', other.sign('message'))).toBeFalse();
  });

  it('encrypts and decrypts payloads', async () => {
    const encrypted = keyPair.encrypt('round-trip');
    const voEncrypted = keyPair.encrypt(new StringValueObject('vo-secret'));

    expect(encrypted).toBeInstanceOf(EncryptedPayload);
    expect(voEncrypted).toBeInstanceOf(EncryptedPayload);
    expect(keyPair.decrypt(encrypted).toString()).toBe('round-trip');

    const other = await KeyPair.generate();
    expect(() => other.decrypt(encrypted)).toThrow();
  });

  it('encrypts the key pair and keeps it functional', async () => {
    const encrypted = await keyPair.encryptKeyPair('password');
    const encryptedWithVo = await keyPair.encryptKeyPair(
      new StringValueObject('password'),
    );
    const signature = await encrypted.sign('message', 'password');

    expect(encrypted).toBeInstanceOf(EncryptedKeyPair);
    expect(encryptedWithVo).toBeInstanceOf(EncryptedKeyPair);
    expect(encrypted.isValidSignature('message', signature)).toBeTrue();
  });
});
