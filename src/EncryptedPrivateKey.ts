import { StringValueObject, ValueObject, assert } from '@haskou/value-objects';

import { InvalidEncryptedPrivateKeyFormatError } from './errors/InvalidEncryptedPrivateKeyFormatError';
import { EncryptedPrivateKeyLegacy } from './internal/EncryptedPrivateKeyLegacy';
import { EncryptedPrivateKeyV2 } from './internal/EncryptedPrivateKeyV2';
import { EncryptedPrivateKeyV3 } from './internal/EncryptedPrivateKeyV3';
import { PrivateKey } from './PrivateKey';
import { CryptoPassword } from './SymmetricKey';

export class EncryptedPrivateKey extends ValueObject<string> {
  private static readonly versions = [
    new EncryptedPrivateKeyLegacy(),
    new EncryptedPrivateKeyV2(),
    new EncryptedPrivateKeyV3(),
  ];

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
    const version = EncryptedPrivateKey.versions.find((handler) =>
      handler.matches(parts),
    );

    assert(version, new InvalidEncryptedPrivateKeyFormatError());

    return version.decrypt(parts, password);
  }

  public needsReEncryption(): boolean {
    const parts = this.valueOf().split('.');
    const version = EncryptedPrivateKey.versions.find((handler) =>
      handler.matches(parts),
    );

    return version ? version.needsReEncryption() : false;
  }
}
