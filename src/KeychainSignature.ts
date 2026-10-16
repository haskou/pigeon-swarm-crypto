import type { KeychainSignaturePayload } from './KeychainSignaturePayload';

import { CanonicalJson } from './CanonicalJson';
import { InvalidKeychainSignatureError } from './errors/InvalidKeychainSignatureError';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

export class KeychainSignature {
  private static readonly DOMAIN = 'pigeon:keychain:v1\n';

  private static content(payload: KeychainSignaturePayload): string {
    const record = PreimageFields.record(
      payload,
      ['encryptedPayload', 'ownerIdentityId', 'timestamp', 'version'],
      ['previousKeychainExternalIdentifier'],
    );

    return (
      this.DOMAIN +
      CanonicalJson.serialize({
        encryptedPayload: PreimageFields.text(record.encryptedPayload),
        ownerIdentityId: PreimageFields.bodyCredential(record.ownerIdentityId),
        previousKeychainExternalIdentifier: PreimageFields.optional(
          record.previousKeychainExternalIdentifier,
          (value) => PreimageFields.text(value),
        ),
        timestamp: PreimageFields.counter(record.timestamp),
        version: PreimageFields.counter(record.version),
      })
    );
  }

  public static signingContent(payload: KeychainSignaturePayload): string {
    return PreimageFields.guarded(InvalidKeychainSignatureError, () =>
      this.content(payload),
    );
  }

  /** Signs with the owner identity key, whose body is `ownerIdentityId`. */
  public static sign(
    payload: KeychainSignaturePayload,
    key: PrivateKey,
  ): Signature {
    return PreimageFields.guarded(InvalidKeychainSignatureError, () =>
      PreimageFields.signFor(
        this.content(payload),
        key,
        payload.ownerIdentityId,
      ),
    );
  }

  public static verify(
    payload: KeychainSignaturePayload,
    signature: Signature,
    key: PublicKey,
  ): void {
    PreimageFields.guarded(InvalidKeychainSignatureError, () =>
      PreimageFields.verifyFor(
        this.content(payload),
        signature,
        key,
        payload.ownerIdentityId,
      ),
    );
  }
}
