import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidCommunityInviteReferenceError } from './errors/InvalidCommunityInviteReferenceError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { PreimageFields } from './internal/PreimageFields';

/**
 * The public reference a node stores for one community invite token, so the
 * token itself never leaves the inviter and the invitee.
 */
export class CommunityInviteReference {
  private static readonly DOMAIN = 'pigeon:community-invite-reference:v1\n';

  /** Unpadded base64url SHA-256 of the domain-separated 32-byte token. */
  public static of(token: string): string {
    return PreimageFields.guarded(InvalidCommunityInviteReferenceError, () => {
      CanonicalBase64Url.decode(token, 32);

      return CanonicalBase64Url.encode(
        sha256(Buffer.from(this.DOMAIN + token, 'utf8')),
      );
    });
  }
}
