import type { DevicePairingCompletionPayload } from './DevicePairingCompletionPayload';

import { DevicePairingPreimage } from './internal/DevicePairingPreimage';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

export class DevicePairingCompletionSignature {
  private static readonly preimage =
    new DevicePairingPreimage<DevicePairingCompletionPayload>(
      'pigeon:device-pairing:completion:v1',
      'completion',
      'authorCredential',
      (value) => {
        const record = PreimageFields.record(value, [
          'authorCredential',
          'encryptedMaterial',
          'epoch',
          'identityId',
          'operationId',
          'pairingId',
          'revision',
          'version',
        ]);

        return {
          authorCredential: PreimageFields.credential(record.authorCredential),
          encryptedMaterial: PreimageFields.text(record.encryptedMaterial),
          epoch: PreimageFields.text(record.epoch),
          identityId: PreimageFields.bodyCredential(record.identityId),
          operationId: PreimageFields.text(record.operationId),
          pairingId: PreimageFields.text(record.pairingId),
          revision: PreimageFields.counter(record.revision),
          version: PreimageFields.literal(record.version, 1),
        };
      },
    );

  public static signingContent(
    completion: DevicePairingCompletionPayload,
  ): string {
    return this.preimage.signingContent(completion);
  }

  public static sign(
    completion: DevicePairingCompletionPayload,
    key: PrivateKey,
  ): Signature {
    return this.preimage.sign(completion, key);
  }

  public static verify(
    completion: DevicePairingCompletionPayload,
    signature: Signature,
    key: PublicKey,
  ): void {
    this.preimage.verify(completion, signature, key);
  }
}
