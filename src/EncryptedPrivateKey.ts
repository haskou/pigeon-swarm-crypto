import { StringValueObject, ValueObject, assert } from '@haskou/value-objects';

import { CryptoPassword } from './CryptoPassword';
import { InvalidEncryptedPrivateKeyFormatError } from './errors/InvalidEncryptedPrivateKeyFormatError';
import { EncryptedPrivateKeyV3 } from './internal/EncryptedPrivateKeyV3';
import { PrivateKey } from './PrivateKey';

export class EncryptedPrivateKey extends ValueObject<string> {
  private static readonly version = new EncryptedPrivateKeyV3();

  public static async create(
    privateKey: PrivateKey,
    password: CryptoPassword,
  ): Promise<EncryptedPrivateKey> {
    return new EncryptedPrivateKey(
      await EncryptedPrivateKeyV3.encrypt(privateKey, password),
    );
  }

  constructor(encryptedPrivateKey: string | StringValueObject) {
    super(encryptedPrivateKey?.valueOf());
  }

  public async decrypt(password: CryptoPassword): Promise<PrivateKey> {
    const parts = this.valueOf().split('.');

    assert(
      EncryptedPrivateKey.version.matches(parts),
      new InvalidEncryptedPrivateKeyFormatError(),
    );

    return EncryptedPrivateKey.version.decrypt(parts, password);
  }
}
