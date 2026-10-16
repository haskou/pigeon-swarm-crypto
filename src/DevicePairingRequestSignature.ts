import type { DevicePairingRequestPayload } from './DevicePairingRequestPayload';

import { DevicePairingPreimage } from './internal/DevicePairingPreimage';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

export class DevicePairingRequestSignature {
  private static readonly preimage =
    new DevicePairingPreimage<DevicePairingRequestPayload>(
      'pigeon:device-pairing:request:v1',
      'request',
      'targetCredential',
      (value) => {
        const record = PreimageFields.record(value, [
          'authorizedAt',
          'invitation',
          'operationId',
          'proofOfPossession',
          'targetCredential',
          'transportPublicKey',
          'version',
        ]);

        return {
          authorizedAt: PreimageFields.counter(record.authorizedAt),
          invitation: PreimageFields.text(
            record.invitation,
            DevicePairingRequestSignature.MAX_INVITATION_LENGTH,
          ),
          operationId: PreimageFields.text(record.operationId),
          proofOfPossession: PreimageFields.signature(record.proofOfPossession),
          targetCredential: PreimageFields.credential(record.targetCredential),
          transportPublicKey: PreimageFields.credential(
            record.transportPublicKey,
          ),
          version: PreimageFields.literal(record.version, 1),
        };
      },
    );

  public static readonly MAX_INVITATION_LENGTH = 32768;

  public static signingContent(request: DevicePairingRequestPayload): string {
    return this.preimage.signingContent(request);
  }

  public static sign(
    request: DevicePairingRequestPayload,
    key: PrivateKey,
  ): Signature {
    return this.preimage.sign(request, key);
  }

  public static verify(
    request: DevicePairingRequestPayload,
    signature: Signature,
    key: PublicKey,
  ): void {
    this.preimage.verify(request, signature, key);
  }
}
