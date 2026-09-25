import { NullObject, ValueObject } from '@haskou/value-objects';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { Buffer } from 'buffer';

import { CryptoPassword } from './CryptoPassword';
import { InvalidProtectedUserRootKeyError } from './errors/InvalidProtectedUserRootKeyError';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { CryptoDerivation } from './internal/CryptoDerivation';
import { StrictBase64 } from './internal/StrictBase64';
import { UserRootKey } from './UserRootKey';
import { UserRootKeySecondFactor } from './UserRootKeySecondFactor';

export class ProtectedUserRootKey extends ValueObject<string> {
  private static readonly VERSION = 'v1';
  private static readonly KDF = 'scrypt';
  private static readonly SCRYPT_N = 262144;
  private static readonly SCRYPT_R = 8;
  private static readonly SCRYPT_P = 1;
  private static readonly COMBINER = 'hkdf-sha256';
  private static readonly CIPHER = 'aes-256-gcm';
  private static readonly SALT_LENGTH = 16;
  private static readonly IV_LENGTH = 12;
  private static readonly TAG_LENGTH = 16;
  private static readonly ROOT_KEY_LENGTH = 32;
  private static readonly EXPECTED_PARTS = 11;
  private static readonly MAX_SERIALIZED_LENGTH = 512;
  private static readonly INFO = Buffer.from(
    'pigeon.user-root-key-protection.v1',
    'utf8',
  );

  private static header(): string[] {
    return [
      this.VERSION,
      this.KDF,
      `N${this.SCRYPT_N}`,
      `r${this.SCRYPT_R}`,
      `p${this.SCRYPT_P}`,
      this.COMBINER,
      this.CIPHER,
    ];
  }

  private static validate(parts: string[]): void {
    if (
      parts.length !== this.EXPECTED_PARTS ||
      parts.slice(0, 7).join('.') !== this.header().join('.')
    )
      throw new InvalidProtectedUserRootKeyError();

    StrictBase64.decodeCanonicalFixedLength(
      parts[7],
      new InvalidProtectedUserRootKeyError(),
      this.SALT_LENGTH,
    );
    StrictBase64.decodeCanonicalFixedLength(
      parts[8],
      new InvalidProtectedUserRootKeyError(),
      this.IV_LENGTH,
    );
    StrictBase64.decodeCanonicalFixedLength(
      parts[9],
      new InvalidProtectedUserRootKeyError(),
      this.TAG_LENGTH,
    );
    StrictBase64.decodeCanonicalFixedLength(
      parts[10],
      new InvalidProtectedUserRootKeyError(),
      this.ROOT_KEY_LENGTH,
    );
  }

  private static async deriveProtectionKey(
    password: CryptoPassword,
    factor: UserRootKeySecondFactor,
    salt: Buffer,
  ): Promise<Buffer> {
    const passwordKey = await CryptoDerivation.scryptAsync(
      password.valueOf(),
      salt,
      this.ROOT_KEY_LENGTH,
      { N: this.SCRYPT_N, p: this.SCRYPT_P, r: this.SCRYPT_R },
    );
    let factorBytes: Buffer | undefined;
    let combined: Uint8Array | undefined;

    try {
      factorBytes = factor.getBuffer();
      combined = concatBytes(passwordKey, factorBytes);
      const derived = hkdf(
        sha256,
        combined,
        salt,
        this.INFO,
        this.ROOT_KEY_LENGTH,
      );

      return Buffer.from(
        derived.buffer as ArrayBuffer,
        derived.byteOffset,
        derived.byteLength,
      );
    } finally {
      passwordKey.fill(0);
      factorBytes?.fill(0);
      combined?.fill(0);
    }
  }

  public static async create(
    rootKey: UserRootKey,
    password: CryptoPassword,
    factor: UserRootKeySecondFactor,
  ): Promise<ProtectedUserRootKey> {
    if (NullObject.isNullObject(rootKey)) {
      throw new InvalidProtectedUserRootKeyError();
    }
    const rootKeyBytes = rootKey.getBuffer();
    let protectionKey: Buffer | undefined;
    let iv: Buffer | undefined;

    try {
      const salt = await CryptoDerivation.randomBytesAsync(this.SALT_LENGTH);
      protectionKey = await this.deriveProtectionKey(password, factor, salt);
      const prefix = [...this.header(), salt.toString('base64')];
      iv = CryptoAdapter.randomBytes(this.IV_LENGTH);
      const { cipherText, tag } = CryptoAdapter.encryptAes256Gcm(
        protectionKey,
        iv,
        rootKeyBytes,
        Buffer.from(prefix.join('.'), 'utf8'),
      );

      return new ProtectedUserRootKey(
        [
          ...prefix,
          iv.toString('base64'),
          Buffer.from(tag).toString('base64'),
          Buffer.from(cipherText).toString('base64'),
        ].join('.'),
      );
    } finally {
      protectionKey?.fill(0);
      rootKeyBytes.fill(0);
      iv?.fill(0);
    }
  }

  public async unlock(
    password: CryptoPassword,
    factor: UserRootKeySecondFactor,
  ): Promise<UserRootKey> {
    try {
      if (this.valueOf().length > ProtectedUserRootKey.MAX_SERIALIZED_LENGTH)
        throw new InvalidProtectedUserRootKeyError();
      const parts = this.valueOf().split('.');
      ProtectedUserRootKey.validate(parts);
      const salt = Buffer.from(parts[7], 'base64');
      const protectionKey = await ProtectedUserRootKey.deriveProtectionKey(
        password,
        factor,
        salt,
      );
      let rootKey: Buffer | undefined;

      try {
        rootKey = CryptoAdapter.decryptAes256Gcm(
          protectionKey,
          Buffer.from(parts[8], 'base64'),
          Buffer.from(parts[10], 'base64'),
          Buffer.from(parts[9], 'base64'),
          Buffer.from(parts.slice(0, 8).join('.'), 'utf8'),
        );

        return UserRootKey.fromBase64(rootKey.toString('base64'));
      } finally {
        protectionKey.fill(0);
        rootKey?.fill(0);
      }
    } catch {
      throw new InvalidProtectedUserRootKeyError();
    }
  }

  public async rewrap(
    currentPassword: CryptoPassword,
    currentFactor: UserRootKeySecondFactor,
    nextPassword: CryptoPassword,
    nextFactor: UserRootKeySecondFactor,
  ): Promise<ProtectedUserRootKey> {
    const rootKey = await this.unlock(currentPassword, currentFactor);

    return ProtectedUserRootKey.create(rootKey, nextPassword, nextFactor);
  }
}
