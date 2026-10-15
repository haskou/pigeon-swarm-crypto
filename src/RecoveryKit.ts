import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidRecoveryKeyError } from './errors/InvalidRecoveryKeyError';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { KeyPair } from './KeyPair';
import { PrivateKey } from './PrivateKey';
import { RecoveryKey } from './RecoveryKey';
import { RecoveryKitMaterial } from './RecoveryKitMaterial';
import { UserRootKey } from './UserRootKey';

export class RecoveryKit {
  private static readonly AUTHORITY_INFO = 'pigeon-swarm:recovery-authority:v1';
  private static readonly IDENTITY_INFO =
    'pigeon-swarm:recovery-identity-signing:v1';

  private static readonly KEY_LENGTH = 32;
  private static readonly ROOT_INFO = 'pigeon-swarm:recovery-user-root:v1';
  private static readonly SALT = 'pigeon-swarm:recovery-kit:v1';

  private static keyPair(seed: Uint8Array): KeyPair {
    try {
      const privateKey = PrivateKey.fromPEM(
        CryptoAdapter.privateKeyToPem(seed),
      );

      return new KeyPair(privateKey.getPublicKey(), privateKey);
    } finally {
      seed.fill(0);
    }
  }

  public static derive(recoveryKey: RecoveryKey): RecoveryKitMaterial {
    try {
      if (!(recoveryKey instanceof RecoveryKey))
        throw new InvalidRecoveryKeyError();
      const recoveryBytes = recoveryKey.getBytes();
      const expand = (salt: Uint8Array, info: string): Uint8Array =>
        hkdf(
          sha256,
          recoveryBytes,
          salt,
          Buffer.from(info, 'utf8'),
          RecoveryKit.KEY_LENGTH,
        );

      try {
        const salt = Buffer.from(RecoveryKit.SALT, 'utf8');
        const identityKeyPair = this.keyPair(
          expand(salt, RecoveryKit.IDENTITY_INFO),
        );
        const root = Buffer.from(expand(salt, RecoveryKit.ROOT_INFO));
        const rootKey = UserRootKey.fromBase64(root.toString('base64'));
        root.fill(0);
        const identityId = identityKeyPair
          .toPrimitives()
          .publicKey.replace('-----BEGIN PUBLIC KEY-----', '')
          .replace('-----END PUBLIC KEY-----', '')
          .replace(/\s+/g, '');
        const recoveryAuthorityKeyPair = this.keyPair(
          expand(
            sha256(Buffer.from(identityId, 'utf8')),
            RecoveryKit.AUTHORITY_INFO,
          ),
        );

        return Object.freeze({
          identityKeyPair,
          recoveryAuthorityKeyPair,
          rootKey,
        });
      } finally {
        recoveryBytes.fill(0);
      }
    } catch {
      throw new InvalidRecoveryKeyError();
    }
  }
}
