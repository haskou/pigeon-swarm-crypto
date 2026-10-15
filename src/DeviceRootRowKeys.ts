import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidDeviceRootRowError } from './errors/InvalidDeviceRootRowError';
import { BoundedText } from './internal/BoundedText';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { KeyMaterial } from './internal/KeyMaterial';
import { SymmetricKey } from './SymmetricKey';

export class DeviceRootRowKeys {
  static readonly #CANARY_PURPOSE = 'canary';
  static readonly #IV_LENGTH = 12;
  static readonly #KEY_LENGTH = 32;
  static readonly #LABEL = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
  static readonly #MAX_AAD_BYTES = 16384;
  static readonly #MAX_IDENTITY_BYTES = 4096;
  static readonly #MAX_LABEL_LENGTH = 64;
  static readonly #MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024;
  static readonly #PURPOSE = /^[a-z][a-z-]{0,31}$/;
  static readonly #TAG_LENGTH = 16;

  readonly #canaryPlaintext: Uint8Array;
  readonly #cipherKey: Uint8Array;
  readonly #identityId: string;
  readonly #tagKey: Uint8Array;

  private static stringList(value: unknown): readonly string[] {
    if (!Array.isArray(value) || value.some((part) => typeof part !== 'string'))
      throw new InvalidDeviceRootRowError();

    return value as readonly string[];
  }

  public static derive(
    root: SymmetricKey,
    label: string,
    identityId: string,
  ): DeviceRootRowKeys {
    try {
      if (
        typeof label !== 'string' ||
        label.length > DeviceRootRowKeys.#MAX_LABEL_LENGTH ||
        !DeviceRootRowKeys.#LABEL.test(label)
      )
        throw new InvalidDeviceRootRowError();
      BoundedText.encode(identityId, DeviceRootRowKeys.#MAX_IDENTITY_BYTES);
      const material = KeyMaterial.of(root);
      const salt = Buffer.from(`${label}:salt`, 'utf8');
      const derive = (info: string): Uint8Array =>
        hkdf(
          sha256,
          material,
          salt,
          Buffer.from(info, 'utf8'),
          DeviceRootRowKeys.#KEY_LENGTH,
        );

      return new DeviceRootRowKeys(
        label,
        identityId,
        derive(`${label}:v1:${identityId}`),
        derive(`${label}:tag:v1:${identityId}`),
      );
    } catch {
      throw new InvalidDeviceRootRowError();
    }
  }

  private constructor(
    label: string,
    identityId: string,
    cipherKey: Uint8Array,
    tagKey: Uint8Array,
  ) {
    this.#canaryPlaintext = Buffer.from(`${label}:canary`, 'utf8');
    this.#cipherKey = cipherKey;
    this.#identityId = identityId;
    this.#tagKey = tagKey;
  }

  private aad(purpose: string, scope: readonly string[]): Uint8Array {
    const aad = Buffer.from(
      JSON.stringify([
        purpose,
        this.#identityId,
        ...DeviceRootRowKeys.stringList(scope),
      ]),
      'utf8',
    );

    if (aad.length > DeviceRootRowKeys.#MAX_AAD_BYTES)
      throw new InvalidDeviceRootRowError();

    return aad;
  }

  private rowAad(purpose: string, scope: readonly string[]): Uint8Array {
    if (
      typeof purpose !== 'string' ||
      !DeviceRootRowKeys.#PURPOSE.test(purpose) ||
      purpose === DeviceRootRowKeys.#CANARY_PURPOSE
    )
      throw new InvalidDeviceRootRowError();

    return this.aad(purpose, scope);
  }

  private sealWith(aad: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (
      !(plaintext instanceof Uint8Array) ||
      plaintext.length > DeviceRootRowKeys.#MAX_PLAINTEXT_BYTES
    )
      throw new InvalidDeviceRootRowError();
    const iv = CryptoAdapter.randomBytes(DeviceRootRowKeys.#IV_LENGTH);

    return Buffer.concat([
      iv,
      gcm(this.#cipherKey, iv, aad).encrypt(plaintext),
    ]);
  }

  private openWith(
    aad: Uint8Array,
    sealed: Uint8Array,
  ): Uint8Array | undefined {
    if (
      !(sealed instanceof Uint8Array) ||
      sealed.length <
        DeviceRootRowKeys.#IV_LENGTH + DeviceRootRowKeys.#TAG_LENGTH ||
      sealed.length >
        DeviceRootRowKeys.#MAX_PLAINTEXT_BYTES +
          DeviceRootRowKeys.#IV_LENGTH +
          DeviceRootRowKeys.#TAG_LENGTH
    )
      return undefined;

    try {
      return gcm(
        this.#cipherKey,
        sealed.subarray(0, DeviceRootRowKeys.#IV_LENGTH),
        aad,
      ).decrypt(sealed.subarray(DeviceRootRowKeys.#IV_LENGTH));
    } catch {
      return undefined;
    }
  }

  public open(
    purpose: string,
    scope: readonly string[],
    sealed: Uint8Array,
  ): Uint8Array | undefined {
    try {
      return this.openWith(this.rowAad(purpose, scope), sealed);
    } catch {
      throw new InvalidDeviceRootRowError();
    }
  }

  public opensCanary(sealed: Uint8Array): boolean {
    return (
      this.openWith(this.aad(DeviceRootRowKeys.#CANARY_PURPOSE, []), sealed) !==
      undefined
    );
  }

  public seal(
    purpose: string,
    scope: readonly string[],
    plaintext: Uint8Array,
  ): Uint8Array {
    try {
      return this.sealWith(this.rowAad(purpose, scope), plaintext);
    } catch {
      throw new InvalidDeviceRootRowError();
    }
  }

  public sealCanary(): Uint8Array {
    try {
      return this.sealWith(
        this.aad(DeviceRootRowKeys.#CANARY_PURPOSE, []),
        this.#canaryPlaintext,
      );
    } catch {
      throw new InvalidDeviceRootRowError();
    }
  }

  public tag(parts: readonly string[]): string {
    try {
      const message = Buffer.from(
        JSON.stringify(DeviceRootRowKeys.stringList(parts)),
        'utf8',
      );

      if (message.length > DeviceRootRowKeys.#MAX_AAD_BYTES)
        throw new InvalidDeviceRootRowError();

      return CanonicalBase64Url.encode(hmac(sha256, this.#tagKey, message));
    } catch {
      throw new InvalidDeviceRootRowError();
    }
  }
}
