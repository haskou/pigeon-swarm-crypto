import { CommunityInvitationFields } from './CommunityInvitationFields';
import { InvalidCommunityInvitationError } from './errors/InvalidCommunityInvitationError';
import { CommunityInvitationPreimage } from './internal/CommunityInvitationPreimage';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';

/**
 * The joiner's consent to join under one invitation, signed with the identity
 * key named in `fields.identityId` and verified under that same id.
 */
export class CommunityInvitationConsent {
  public static contentOf(fields: CommunityInvitationFields): string {
    return PreimageFields.guarded(InvalidCommunityInvitationError, () =>
      CommunityInvitationPreimage.content(
        CommunityInvitationPreimage.CONSENT,
        fields,
      ),
    );
  }

  public static sign(
    fields: CommunityInvitationFields,
    identityKey: PrivateKey,
  ): string {
    return PreimageFields.guarded(InvalidCommunityInvitationError, () => {
      PreimageFields.check(
        identityKey instanceof PrivateKey &&
          PreimageFields.credentialBody(identityKey.getPublicKey()) ===
            fields.identityId,
      );

      return CommunityInvitationPreimage.sign(
        CommunityInvitationPreimage.CONSENT,
        fields,
        identityKey,
      );
    });
  }

  public static verify(
    fields: CommunityInvitationFields,
    consent: string,
  ): void {
    PreimageFields.guarded(InvalidCommunityInvitationError, () =>
      CommunityInvitationPreimage.verify(
        CommunityInvitationPreimage.CONSENT,
        fields,
        consent,
        CommunityInvitationPreimage.identityKey(fields.identityId),
      ),
    );
  }
}
