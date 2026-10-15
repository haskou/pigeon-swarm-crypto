import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidKeyFingerprintError } from './errors/InvalidKeyFingerprintError';
import { PublicKey } from './PublicKey';

export class KeyFingerprint {
  private static readonly DISPLAY_BYTES = 16;
  private static readonly MAX_INPUT_BYTES = 65536;
  private static readonly SECRET_DOMAIN = 'pigeon-swarm:key-fingerprint:v1\n';

  private static format(bytes: Uint8Array): string {
    if (
      !(bytes instanceof Uint8Array) ||
      bytes.length > KeyFingerprint.MAX_INPUT_BYTES
    )
      throw new InvalidKeyFingerprintError();

    return Buffer.from(sha256(bytes).subarray(0, KeyFingerprint.DISPLAY_BYTES))
      .toString('hex')
      .toUpperCase()
      .replace(/(.{4})(?!$)/g, '$1 ');
  }

  public static ofPublicBytes(bytes: Uint8Array): string {
    return this.format(bytes);
  }

  public static ofPublicKey(publicKey: PublicKey): string {
    try {
      if (!(publicKey instanceof PublicKey))
        throw new InvalidKeyFingerprintError();

      return this.format(
        Buffer.from(
          publicKey
            .valueOf()
            .replace('-----BEGIN PUBLIC KEY-----', '')
            .replace('-----END PUBLIC KEY-----', '')
            .replace(/\s+/g, ''),
          'base64',
        ),
      );
    } catch {
      throw new InvalidKeyFingerprintError();
    }
  }

  public static ofSecret(secret: Uint8Array): string {
    if (!(secret instanceof Uint8Array)) throw new InvalidKeyFingerprintError();

    return this.format(
      Buffer.concat([
        Buffer.from(KeyFingerprint.SECRET_DOMAIN, 'utf8'),
        secret,
      ]),
    );
  }
}
