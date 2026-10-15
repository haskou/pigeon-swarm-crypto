import type { IdentityProfile } from './IdentityProfile';
import type { IdentitySignaturePayload } from './IdentitySignaturePayload';

import { CanonicalJson } from './CanonicalJson';
import { DeviceCredentialCommitment } from './DeviceCredentialCommitment';
import { InvalidIdentitySignatureError } from './errors/InvalidIdentitySignatureError';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

export class IdentitySignature {
  private static readonly PROFILE_OPTIONAL = [
    'banner',
    'biography',
    'handle',
    'picture',
  ] as const;

  private static profile(value: unknown): IdentityProfile {
    const record = PreimageFields.record(
      value,
      ['name'],
      this.PROFILE_OPTIONAL,
    );

    return {
      ...Object.fromEntries(
        this.PROFILE_OPTIONAL.map((field) => [
          field,
          PreimageFields.optional(record[field], (present) =>
            PreimageFields.text(present),
          ),
        ]),
      ),
      name: PreimageFields.text(record.name),
    };
  }

  private static content(payload: IdentitySignaturePayload): string {
    const record = PreimageFields.record(
      payload,
      [
        'authorizationRevision',
        'deviceCredential',
        'deviceCredentialCommitment',
        'id',
        'networks',
        'profile',
        'recoveryAuthority',
        'timestamp',
        'version',
      ],
      ['admissionNonce', 'mailboxHome', 'previousIdentityExternalIdentifier'],
    );
    const deviceCredential = PreimageFields.credential(record.deviceCredential);
    PreimageFields.check(
      record.deviceCredentialCommitment ===
        DeviceCredentialCommitment.of(new PublicKey(deviceCredential)),
    );

    return CanonicalJson.serialize({
      admissionNonce: PreimageFields.optional(record.admissionNonce, (value) =>
        PreimageFields.text(value),
      ),
      authorizationRevision: PreimageFields.counter(
        record.authorizationRevision,
      ),
      deviceCredential,
      deviceCredentialCommitment: record.deviceCredentialCommitment,
      id: PreimageFields.bodyCredential(record.id),
      mailboxHome: PreimageFields.optional(record.mailboxHome, (value) =>
        PreimageFields.text(value),
      ),
      networks: PreimageFields.list(record.networks, (network) =>
        PreimageFields.text(network),
      ),
      previousIdentityExternalIdentifier: PreimageFields.optional(
        record.previousIdentityExternalIdentifier,
        (value) => PreimageFields.text(value),
      ),
      profile: this.profile(record.profile),
      recoveryAuthority: PreimageFields.credential(record.recoveryAuthority),
      timestamp: PreimageFields.counter(record.timestamp),
      version: PreimageFields.counter(record.version),
    });
  }

  public static signingContent(payload: IdentitySignaturePayload): string {
    return PreimageFields.guarded(InvalidIdentitySignatureError, () =>
      this.content(payload),
    );
  }

  /** Signs with the identity key, whose credential body is `payload.id`. */
  public static sign(
    payload: IdentitySignaturePayload,
    key: PrivateKey,
  ): Signature {
    return PreimageFields.guarded(InvalidIdentitySignatureError, () =>
      PreimageFields.signFor(this.content(payload), key, payload.id),
    );
  }

  public static verify(
    payload: IdentitySignaturePayload,
    signature: Signature,
    key: PublicKey,
  ): void {
    PreimageFields.guarded(InvalidIdentitySignatureError, () =>
      PreimageFields.verifyFor(
        this.content(payload),
        signature,
        key,
        payload.id,
      ),
    );
  }
}
