import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';

import { InvalidBearerCapabilityError } from './errors/InvalidBearerCapabilityError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';

export class BearerCapability {
  private static readonly tokenPattern = /^[A-Za-z0-9_-]{20,128}$/;
  private static readonly hashPattern = /^[0-9a-f]{64}$/;

  private static isToken(token: unknown): token is string {
    return typeof token === 'string' && this.tokenPattern.test(token);
  }

  public static generate(): { hash: string; token: string } {
    const token = CanonicalBase64Url.encode(randomBytes(32));

    return { hash: this.hash(token), token };
  }

  public static hash(token: string): string {
    if (!this.isToken(token)) throw new InvalidBearerCapabilityError();

    return bytesToHex(sha256(utf8ToBytes(token)));
  }

  public static verify(token: unknown, expectedHash: unknown): boolean {
    if (
      !this.isToken(token) ||
      typeof expectedHash !== 'string' ||
      !this.hashPattern.test(expectedHash)
    )
      return false;
    const actual = sha256(utf8ToBytes(token));
    let difference = 0;
    for (let index = 0; index < actual.length; index++) {
      const delta =
        actual[index] -
        Number.parseInt(expectedHash.slice(index * 2, index * 2 + 2), 16);
      difference += delta * delta;
    }

    return difference === 0;
  }
}
