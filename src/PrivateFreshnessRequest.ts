import type { PrivateFreshnessRequestInput } from './PrivateFreshnessRequestInput';

import { CanonicalJson } from './CanonicalJson';
import { InvalidPrivateFreshnessRequestError } from './errors/InvalidPrivateFreshnessRequestError';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateFreshnessEncoding } from './internal/PrivateFreshnessEncoding';

/**
 * Builds the exact request JSON that `PrivateFreshnessProof.verify` expects:
 * canonical JSON with `version: 1` and 32-byte unpadded base64url values.
 */
export class PrivateFreshnessRequest {
  public static serialize(input: PrivateFreshnessRequestInput): string {
    return PreimageFields.guarded(InvalidPrivateFreshnessRequestError, () => {
      const request = {
        ...PreimageFields.record(input, [
          'batchCommitment',
          'expectedHeadHash',
          'expectedRevision',
          'nonce',
          'scopeId',
        ]),
        version: 1,
      };
      PrivateFreshnessEncoding.validateRequest(request);

      return CanonicalJson.serialize(request);
    });
  }
}
