import { CommunityInvitationFields } from './CommunityInvitationFields';
import { InvalidCommunityInvitationError } from './errors/InvalidCommunityInvitationError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CommunityInvitationPreimage } from './internal/CommunityInvitationPreimage';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';

/**
 * The key an invitation link carries as a secret. Only this class holds the
 * private key, and it signs nothing but possession proofs.
 */
export class CommunityInvitationKey {
  static readonly #INFO = 'pigeon:community-invitation-key:v1';
  static readonly #LENGTH = 32;

  readonly #privateKey: PrivateKey;
  readonly #publicKey: string;

  public static fromSecret(secret: string): CommunityInvitationKey {
    return PreimageFields.guarded(InvalidCommunityInvitationError, () => {
      const bytes = CanonicalBase64Url.decode(
        secret,
        CommunityInvitationKey.#LENGTH,
      );
      const seed = CryptoAdapter.hkdfSha256(
        bytes,
        CommunityInvitationKey.#INFO,
        CommunityInvitationKey.#LENGTH,
      );

      try {
        return new CommunityInvitationKey(PrivateKey.fromSeed(seed));
      } finally {
        bytes.fill(0);
        seed.fill(0);
      }
    });
  }

  /** A fresh secret for a new link, and the key it derives. */
  public static generate(): { key: CommunityInvitationKey; secret: string } {
    const bytes = CryptoAdapter.randomBytes(CommunityInvitationKey.#LENGTH);

    try {
      const secret = CanonicalBase64Url.encode(bytes);

      return { key: CommunityInvitationKey.fromSecret(secret), secret };
    } finally {
      bytes.fill(0);
    }
  }

  /** Returns the key text itself once it decodes strictly to a usable key. */
  public static parsePublicKey(invitationKey: unknown): string {
    return PreimageFields.guarded(InvalidCommunityInvitationError, () => {
      CommunityInvitationPreimage.invitationKey(invitationKey);

      return invitationKey as string;
    });
  }

  private constructor(privateKey: PrivateKey) {
    this.#privateKey = privateKey;
    this.#publicKey = CanonicalBase64Url.encode(
      CryptoAdapter.publicKeyToBytes(
        CryptoAdapter.getPublicKey(privateKey.valueOf()),
      ),
    );
  }

  public publicKey(): string {
    return this.#publicKey;
  }

  /** Proves that whoever admits `fields.identityId` holds the link secret. */
  public signPossession(fields: CommunityInvitationFields): string {
    return PreimageFields.guarded(InvalidCommunityInvitationError, () =>
      CommunityInvitationPreimage.sign(
        CommunityInvitationPreimage.POSSESSION,
        fields,
        this.#privateKey,
      ),
    );
  }

  public toJSON(): never {
    throw new InvalidCommunityInvitationError();
  }
}
