import type { Cipher } from '@noble/ciphers/utils.js';

import { gcm } from '@noble/ciphers/aes.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidHistoryBackupError } from './errors/InvalidHistoryBackupError';
import { BoundedText } from './internal/BoundedText';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { KeyMaterial } from './internal/KeyMaterial';
import { SymmetricKey } from './SymmetricKey';

export class HistoryBackupFile {
  private static readonly FORMAT = 'pigeon-swarm-backup';
  private static readonly IV_LENGTH = 12;
  private static readonly KEY_LENGTH = 32;
  private static readonly MAX_IDENTITY_BYTES = 4096;
  private static readonly SALT = 'pigeon-swarm:history-backup:salt';
  private static readonly TAG_LENGTH = 16;
  private static readonly VERSION = 1;

  public static readonly MAX_PLAINTEXT_BYTES = 128 * 1024 * 1024;

  private static cipher(
    root: SymmetricKey,
    identityId: string,
    iv: Uint8Array,
  ): Cipher {
    BoundedText.encode(identityId, HistoryBackupFile.MAX_IDENTITY_BYTES);
    const key = hkdf(
      sha256,
      KeyMaterial.of(root),
      Buffer.from(HistoryBackupFile.SALT, 'utf8'),
      Buffer.from(`pigeon-swarm:history-backup:v1:${identityId}`, 'utf8'),
      HistoryBackupFile.KEY_LENGTH,
    );

    return gcm(
      key,
      iv,
      Buffer.from(
        JSON.stringify([
          HistoryBackupFile.FORMAT,
          HistoryBackupFile.VERSION,
          identityId,
        ]),
        'utf8',
      ),
    );
  }

  private static serialize(ciphertext: string, iv: string): string {
    return JSON.stringify({
      ciphertext,
      format: HistoryBackupFile.FORMAT,
      iv,
      version: HistoryBackupFile.VERSION,
    });
  }

  public static seal(
    root: SymmetricKey,
    identityId: string,
    plaintext: Uint8Array,
  ): string {
    try {
      if (
        !(plaintext instanceof Uint8Array) ||
        plaintext.length > HistoryBackupFile.MAX_PLAINTEXT_BYTES
      )
        throw new InvalidHistoryBackupError();
      const iv = CryptoAdapter.randomBytes(HistoryBackupFile.IV_LENGTH);

      return this.serialize(
        CanonicalBase64Url.encode(
          this.cipher(root, identityId, iv).encrypt(plaintext),
        ),
        CanonicalBase64Url.encode(iv),
      );
    } catch {
      throw new InvalidHistoryBackupError();
    }
  }

  public static open(
    root: SymmetricKey,
    identityId: string,
    file: string,
  ): Uint8Array {
    try {
      const maxCiphertextLength =
        HistoryBackupFile.MAX_PLAINTEXT_BYTES + HistoryBackupFile.TAG_LENGTH;

      if (
        typeof file !== 'string' ||
        file.length > Math.ceil((maxCiphertextLength * 4) / 3) + 128
      )
        throw new InvalidHistoryBackupError();
      const { ciphertext, iv } = JSON.parse(file) as Record<string, unknown>;

      if (
        typeof ciphertext !== 'string' ||
        typeof iv !== 'string' ||
        this.serialize(ciphertext, iv) !== file
      )
        throw new InvalidHistoryBackupError();
      const sealed = CanonicalBase64Url.decodeBounded(
        ciphertext,
        maxCiphertextLength,
      );

      return this.cipher(
        root,
        identityId,
        CanonicalBase64Url.decode(iv, HistoryBackupFile.IV_LENGTH),
      ).decrypt(sealed);
    } catch {
      throw new InvalidHistoryBackupError();
    }
  }
}
