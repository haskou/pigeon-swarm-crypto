import { sha512 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidSafetyNumberError } from './errors/InvalidSafetyNumberError';
import { BoundedText } from './internal/BoundedText';

export class SafetyNumber {
  private static readonly BYTES_PER_GROUP = 5;
  private static readonly DOMAIN = 'pigeon-swarm:safety-number:v1';
  private static readonly GROUP_COUNT = 12;
  private static readonly GROUP_MODULUS = 100000;
  private static readonly MAX_IDENTITY_BYTES = 4096;

  private static identity(identityId: string): string {
    BoundedText.encode(identityId, SafetyNumber.MAX_IDENTITY_BYTES);

    if (identityId.includes('\n')) throw new InvalidSafetyNumberError();

    return identityId;
  }

  public static between(
    firstIdentityId: string,
    secondIdentityId: string,
  ): readonly string[] {
    try {
      const first = this.identity(firstIdentityId);
      const second = this.identity(secondIdentityId);
      const ordered = first <= second ? [first, second] : [second, first];
      const digest = sha512(
        Buffer.from([SafetyNumber.DOMAIN, ...ordered].join('\n'), 'utf8'),
      );

      return Object.freeze(
        Array.from({ length: SafetyNumber.GROUP_COUNT }, (_, group) =>
          String(
            digest
              .subarray(
                group * SafetyNumber.BYTES_PER_GROUP,
                (group + 1) * SafetyNumber.BYTES_PER_GROUP,
              )
              .reduce((value, byte) => value * 256 + byte, 0) %
              SafetyNumber.GROUP_MODULUS,
          ).padStart(5, '0'),
        ),
      );
    } catch {
      throw new InvalidSafetyNumberError();
    }
  }
}
