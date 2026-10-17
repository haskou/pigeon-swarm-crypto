import { CommunityInvitationFields } from './CommunityInvitationFields';
import { InvalidCommunityInvitationError } from './errors/InvalidCommunityInvitationError';
import { CommunityInvitationPreimage } from './internal/CommunityInvitationPreimage';
import { PreimageFields } from './internal/PreimageFields';

/**
 * Proof that the joiner holds the link secret. `CommunityInvitationKey`
 * signs it; anyone verifies it under the invitation's `invitationKey`.
 */
export class CommunityInvitationPossession {
  public static contentOf(fields: CommunityInvitationFields): string {
    return PreimageFields.guarded(InvalidCommunityInvitationError, () =>
      CommunityInvitationPreimage.content(
        CommunityInvitationPreimage.POSSESSION,
        fields,
      ),
    );
  }

  public static verify(
    fields: CommunityInvitationFields,
    possession: string,
    invitationKey: string,
  ): void {
    PreimageFields.guarded(InvalidCommunityInvitationError, () =>
      CommunityInvitationPreimage.verify(
        CommunityInvitationPreimage.POSSESSION,
        fields,
        possession,
        CommunityInvitationPreimage.invitationKey(invitationKey),
      ),
    );
  }
}
