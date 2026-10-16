import type { DeviceSealedSecretPayload } from './DeviceSealedSecretPayload';

import { CanonicalJson } from './CanonicalJson';
import { InvalidDeviceSealedSecretError } from './errors/InvalidDeviceSealedSecretError';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

export class DeviceSealedSecretSignature {
  private static readonly PURPOSE = 'pigeon:device-sealed-secret:v1';

  private static content(payload: DeviceSealedSecretPayload): string {
    const record = PreimageFields.record(payload, [
      'authorizationRevision',
      'generation',
      'identityId',
      'publisherCredential',
      'recipientCredential',
      'sealedSecret',
    ]);

    return CanonicalJson.serialize({
      authorizationRevision: PreimageFields.counter(
        record.authorizationRevision,
      ),
      generation: PreimageFields.counter(record.generation),
      identityId: PreimageFields.bodyCredential(record.identityId),
      publisherCredential: PreimageFields.bodyCredential(
        record.publisherCredential,
      ),
      purpose: this.PURPOSE,
      recipientCredential: PreimageFields.bodyCredential(
        record.recipientCredential,
      ),
      sealedSecret: PreimageFields.text(record.sealedSecret),
    });
  }

  public static signingContent(payload: DeviceSealedSecretPayload): string {
    return PreimageFields.guarded(InvalidDeviceSealedSecretError, () =>
      this.content(payload),
    );
  }

  /** Signs with the publisher device key named by `publisherCredential`. */
  public static sign(
    payload: DeviceSealedSecretPayload,
    key: PrivateKey,
  ): Signature {
    return PreimageFields.guarded(InvalidDeviceSealedSecretError, () =>
      PreimageFields.signFor(
        this.content(payload),
        key,
        payload.publisherCredential,
      ),
    );
  }

  public static verify(
    payload: DeviceSealedSecretPayload,
    signature: Signature,
    key: PublicKey,
  ): void {
    PreimageFields.guarded(InvalidDeviceSealedSecretError, () =>
      PreimageFields.verifyFor(
        this.content(payload),
        signature,
        key,
        payload.publisherCredential,
      ),
    );
  }
}
