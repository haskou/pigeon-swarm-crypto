import { UUID } from '@haskou/value-objects';
import { Buffer } from 'buffer';

import { CanonicalJson } from '../CanonicalJson';
import { PrivateKey } from '../PrivateKey';
import { CanonicalBase64Url } from './CanonicalBase64Url';
import { CryptoAdapter } from './CryptoAdapter';
import { PreimageFields } from './PreimageFields';

/**
 * The shared body of both invitation proofs and the strict decoding of their
 * keys and signatures. Callers map every failure to their own error.
 */
export class CommunityInvitationPreimage {
  static readonly #COMMUNITY_ID = /^[A-Za-z0-9_-]{1,128}$/;

  static readonly #FIELDS = [
    'communityId',
    'identityId',
    'invitationId',
    'networkId',
  ];

  static readonly #ID_LENGTH = 32;

  static readonly #KEY_LENGTH = 32;

  static readonly #SIGNATURE_LENGTH = 64;

  public static readonly POSSESSION =
    'pigeon:community-invitation-possession:v1\n';

  public static readonly CONSENT = 'pigeon:community-invitation-consent:v1\n';

  /** Refuses aliases: only the canonical SPKI body of a strict key passes. */
  public static identityKey(identityId: unknown): Uint8Array {
    const key = CryptoAdapter.publicKeyToStrictBytes(
      `-----BEGIN PUBLIC KEY-----\n${PreimageFields.text(identityId)}\n-----END PUBLIC KEY-----\n`,
    );
    PreimageFields.check(CryptoAdapter.isStrictEd25519PublicKey(key));

    return key;
  }

  public static invitationKey(invitationKey: unknown): Uint8Array {
    const key = CanonicalBase64Url.decode(
      invitationKey,
      CommunityInvitationPreimage.#KEY_LENGTH,
    );
    PreimageFields.check(CryptoAdapter.isStrictEd25519PublicKey(key));

    return key;
  }

  public static content(domain: string, value: unknown): string {
    const fields = PreimageFields.record(
      value,
      CommunityInvitationPreimage.#FIELDS,
    );
    const identityId = PreimageFields.text(fields.identityId);
    CommunityInvitationPreimage.identityKey(identityId);
    CanonicalBase64Url.decode(
      fields.invitationId,
      CommunityInvitationPreimage.#ID_LENGTH,
    );

    return `${domain}${CanonicalJson.serialize({
      communityId: PreimageFields.pattern(
        fields.communityId,
        CommunityInvitationPreimage.#COMMUNITY_ID,
      ),
      identityId,
      invitationId: fields.invitationId,
      networkId: new UUID(PreimageFields.text(fields.networkId)).valueOf(),
    })}`;
  }

  public static sign(domain: string, fields: unknown, key: PrivateKey): string {
    const content = CommunityInvitationPreimage.content(domain, fields);

    return CanonicalBase64Url.encode(
      CryptoAdapter.sign(Buffer.from(content), key.valueOf()),
    );
  }

  /** Accepts only the canonical 86-character text of a strict signature. */
  public static verify(
    domain: string,
    fields: unknown,
    signature: unknown,
    key: Uint8Array,
  ): void {
    const content = CommunityInvitationPreimage.content(domain, fields);
    PreimageFields.check(
      CryptoAdapter.verify(
        CanonicalBase64Url.decode(
          signature,
          CommunityInvitationPreimage.#SIGNATURE_LENGTH,
        ),
        Buffer.from(content),
        key,
      ),
    );
  }
}
