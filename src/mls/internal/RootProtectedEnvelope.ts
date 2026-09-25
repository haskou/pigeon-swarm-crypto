import { NullObject } from '@haskou/value-objects';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { CryptoAdapter } from '../../internal/CryptoAdapter';
import { StrictBase64 } from '../../internal/StrictBase64';
import { UserRootKey } from '../../UserRootKey';
import { InvalidMlsStateError } from '../InvalidMlsStateError';

export class RootProtectedEnvelope {
  private static readonly HEADER = ['v1', 'hkdf-sha256', 'aes-256-gcm'];

  private static readonly SALT_LENGTH = 16;
  private static readonly IV_LENGTH = 12;
  private static readonly TAG_LENGTH = 16;

  private static decodeCanonical(value: string): Buffer {
    const decoded = StrictBase64.decode(value, new InvalidMlsStateError());

    if (decoded.toString('base64') !== value) throw new InvalidMlsStateError();

    return decoded;
  }

  private static deriveKey(
    rootKey: UserRootKey,
    salt: Uint8Array,
    domain: string,
  ): Buffer {
    if (NullObject.isNullObject(rootKey)) throw new InvalidMlsStateError();
    const rootBytes = rootKey.getBuffer();

    try {
      const derived = hkdf(
        sha256,
        rootBytes,
        salt,
        Buffer.from(domain, 'utf8'),
        32,
      );

      return Buffer.from(
        derived.buffer as ArrayBuffer,
        derived.byteOffset,
        derived.byteLength,
      );
    } finally {
      rootBytes.fill(0);
    }
  }

  private static parse(
    serialized: string,
    maxPlaintextBytes: number,
  ): string[] {
    try {
      if (
        typeof serialized !== 'string' ||
        serialized.length > maxPlaintextBytes * 2
      ) {
        throw new InvalidMlsStateError();
      }
      const parts = serialized.split('.');

      if (
        parts.length !== 7 ||
        parts.slice(0, 3).join('.') !== this.HEADER.join('.')
      ) {
        throw new InvalidMlsStateError();
      }
      StrictBase64.decodeCanonicalFixedLength(
        parts[3],
        new InvalidMlsStateError(),
        this.SALT_LENGTH,
      ).fill(0);
      StrictBase64.decodeCanonicalFixedLength(
        parts[4],
        new InvalidMlsStateError(),
        this.IV_LENGTH,
      ).fill(0);
      StrictBase64.decodeCanonicalFixedLength(
        parts[5],
        new InvalidMlsStateError(),
        this.TAG_LENGTH,
      ).fill(0);
      const ciphertext = this.decodeCanonical(parts[6]);

      if (ciphertext.length === 0 || ciphertext.length > maxPlaintextBytes) {
        throw new InvalidMlsStateError();
      }
      ciphertext.fill(0);

      return parts;
    } catch {
      throw new InvalidMlsStateError();
    }
  }

  public static protect(
    plaintext: Uint8Array,
    rootKey: UserRootKey,
    domain: string,
    maxPlaintextBytes: number,
  ): string {
    if (
      !(plaintext instanceof Uint8Array) ||
      plaintext.length === 0 ||
      plaintext.length > maxPlaintextBytes
    ) {
      throw new InvalidMlsStateError();
    }
    const salt = CryptoAdapter.randomBytes(this.SALT_LENGTH);
    const iv = CryptoAdapter.randomBytes(this.IV_LENGTH);
    const key = this.deriveKey(rootKey, salt, domain);
    const prefix = [...this.HEADER, salt.toString('base64')];

    try {
      const encrypted = CryptoAdapter.encryptAes256Gcm(
        key,
        iv,
        plaintext,
        Buffer.from([...prefix, domain].join('.'), 'utf8'),
      );

      return [
        ...prefix,
        iv.toString('base64'),
        Buffer.from(encrypted.tag).toString('base64'),
        Buffer.from(encrypted.cipherText).toString('base64'),
      ].join('.');
    } finally {
      salt.fill(0);
      iv.fill(0);
      key.fill(0);
    }
  }

  public static unlock(
    serialized: string,
    rootKey: UserRootKey,
    domain: string,
    maxPlaintextBytes: number,
  ): Uint8Array {
    try {
      const parts = this.parse(serialized, maxPlaintextBytes);
      const salt = this.decodeCanonical(parts[3]);
      const key = this.deriveKey(rootKey, salt, domain);
      let plaintext: Buffer | undefined;

      try {
        plaintext = CryptoAdapter.decryptAes256Gcm(
          key,
          Buffer.from(parts[4], 'base64'),
          Buffer.from(parts[6], 'base64'),
          Buffer.from(parts[5], 'base64'),
          Buffer.from([...parts.slice(0, 4), domain].join('.'), 'utf8'),
        );

        if (plaintext.length > maxPlaintextBytes) {
          throw new InvalidMlsStateError();
        }

        return new Uint8Array(plaintext);
      } finally {
        salt.fill(0);
        key.fill(0);
        plaintext?.fill(0);
      }
    } catch {
      throw new InvalidMlsStateError();
    }
  }

  public static validate(serialized: string, maxPlaintextBytes: number): void {
    this.parse(serialized, maxPlaintextBytes);
  }
}
