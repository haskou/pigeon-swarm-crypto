import { scryptAsync } from '@noble/hashes/scrypt.js';
import { Buffer } from 'buffer';

import { CryptoAdapter } from './CryptoAdapter';
import { NodeLikeCrypto } from './NodeLikeCrypto';

export class CryptoDerivation {
  public static scryptAsync(
    password: string,
    salt: Buffer,
    keylen: number,
    options: { N: number; r: number; p: number },
    cryptoModule?: NodeLikeCrypto,
  ): Promise<Buffer> {
    if (cryptoModule?.scrypt) {
      return new Promise<Buffer>((resolve, reject) => {
        cryptoModule.scrypt!(password, salt, keylen, options, (err, key) => {
          if (err) reject(err);
          else resolve(key);
        });
      });
    }

    return scryptAsync(password, salt, { ...options, dkLen: keylen }).then(
      Buffer.from,
    );
  }

  public static async randomBytesAsync(
    size: number,
    cryptoModule?: NodeLikeCrypto,
  ): Promise<Buffer> {
    if (cryptoModule?.randomBytes) {
      return new Promise<Buffer>((resolve, reject) => {
        cryptoModule.randomBytes!(size, (err, bytes) => {
          if (err) reject(err);
          else resolve(bytes);
        });
      });
    }

    return CryptoAdapter.randomBytes(size);
  }
}
