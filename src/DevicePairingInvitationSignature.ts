import type { DevicePairingInvitationPayload } from './DevicePairingInvitationPayload';

import { DevicePairingPreimage } from './internal/DevicePairingPreimage';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

export class DevicePairingInvitationSignature {
  private static readonly preimage =
    new DevicePairingPreimage<DevicePairingInvitationPayload>(
      'pigeon:device-pairing:invitation:v1',
      'invitation',
      'authorCredential',
      (value) => {
        const record = PreimageFields.record(value, [
          'authorCredential',
          'epoch',
          'expiresAt',
          'identityId',
          'pairingId',
          'revision',
          'version',
        ]);

        return {
          authorCredential: PreimageFields.credential(record.authorCredential),
          epoch: PreimageFields.text(record.epoch),
          expiresAt: PreimageFields.counter(record.expiresAt),
          identityId: PreimageFields.bodyCredential(record.identityId),
          pairingId: PreimageFields.text(record.pairingId),
          revision: PreimageFields.counter(record.revision),
          version: PreimageFields.literal(record.version, 1),
        };
      },
    );

  public static signingContent(
    invitation: DevicePairingInvitationPayload,
  ): string {
    return this.preimage.signingContent(invitation);
  }

  public static sign(
    invitation: DevicePairingInvitationPayload,
    key: PrivateKey,
  ): Signature {
    return this.preimage.sign(invitation, key);
  }

  public static verify(
    invitation: DevicePairingInvitationPayload,
    signature: Signature,
    key: PublicKey,
  ): void {
    this.preimage.verify(invitation, signature, key);
  }
}
