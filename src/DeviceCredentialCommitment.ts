import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { PublicKey } from './PublicKey';

/** Lowercase hex SHA-256 of a device credential in its PEM form. */
export class DeviceCredentialCommitment {
  public static of(credential: PublicKey): string {
    return Buffer.from(
      sha256(Buffer.from(credential.toString(), 'utf8')),
    ).toString('hex');
  }
}
