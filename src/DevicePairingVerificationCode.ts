import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import type { DevicePairingVerificationInput } from './DevicePairingVerificationInput';

import { CanonicalJson } from './CanonicalJson';
import { InvalidDevicePairingError } from './errors/InvalidDevicePairingError';
import { PreimageFields } from './internal/PreimageFields';

/**
 * Short authentication string: the first 8 bytes of the SHA-256 of the
 * domain-separated input, as a big-endian integer modulo 10^10, shown as two
 * zero-padded groups of five digits.
 */
export class DevicePairingVerificationCode {
  private static readonly DOMAIN = 'pigeon:device-pairing:verification:v1';
  private static readonly DIGITS = 10;

  public static of(input: DevicePairingVerificationInput): string {
    return PreimageFields.guarded(InvalidDevicePairingError, () => {
      const record = PreimageFields.record(input, [
        'operationId',
        'pairingId',
        'targetCredential',
        'transportPublicKey',
      ]);
      const digest = sha256(
        Buffer.from(
          CanonicalJson.serialize({
            domain: this.DOMAIN,
            operationId: PreimageFields.text(record.operationId),
            pairingId: PreimageFields.text(record.pairingId),
            targetCredential: PreimageFields.credential(
              record.targetCredential,
            ),
            transportPublicKey: PreimageFields.credential(
              record.transportPublicKey,
            ),
          }),
          'utf8',
        ),
      );
      const digits = (
        BigInt(`0x${Buffer.from(digest.subarray(0, 8)).toString('hex')}`) %
        BigInt(10) ** BigInt(this.DIGITS)
      )
        .toString()
        .padStart(this.DIGITS, '0');

      return `${digits.slice(0, 5)} ${digits.slice(5)}`;
    });
  }
}
