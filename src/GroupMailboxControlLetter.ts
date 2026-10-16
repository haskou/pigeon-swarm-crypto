import type { GroupMailboxControlLetterDraft } from './GroupMailboxControlLetterDraft';
import type { GroupMailboxControlLetterFields } from './GroupMailboxControlLetterFields';
import type { OpenedGroupMailboxControlLetter } from './OpenedGroupMailboxControlLetter';

import { CanonicalJson } from './CanonicalJson';
import { EncryptedPayload } from './EncryptedPayload';
import { InvalidGroupMailboxControlLetterError } from './errors/InvalidGroupMailboxControlLetterError';
import { BoundedText } from './internal/BoundedText';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { PreimageFields } from './internal/PreimageFields';
import { StrictCanonicalJson } from './internal/StrictCanonicalJson';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

/**
 * A group mailbox control record that the sender identity signs and seals
 * to one recipient identity.
 */
export class GroupMailboxControlLetter {
  private static readonly DOMAIN = 'pigeon:group-mailbox-control-letter:v1\n';
  private static readonly DRAFT_FIELDS = [
    'conversationId',
    'payload',
    'recipientIdentityId',
    'sentAt',
  ] as const;

  private static readonly KIND = 'group-mailbox-control-letter';
  private static readonly SIGNED_FIELDS = [
    'conversationId',
    'payload',
    'recipientIdentityId',
    'senderIdentityId',
    'sentAt',
  ] as const;

  private static readonly UTF8 = new TextDecoder('utf-8', { fatal: true });

  public static readonly MAX_CONVERSATION_ID_BYTES = 256;
  public static readonly MAX_PAYLOAD_BYTES = 65536;
  public static readonly MAX_SEALED_LENGTH = 524288;

  private static identityKey(identityId: string): PublicKey {
    return new PublicKey(
      `-----BEGIN PUBLIC KEY-----\n${identityId}\n-----END PUBLIC KEY-----\n`,
    );
  }

  private static payload(value: unknown): Uint8Array {
    PreimageFields.check(typeof value === 'string');
    const bytes = CanonicalBase64Url.decodeBounded(
      value as string,
      this.MAX_PAYLOAD_BYTES,
    );

    return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.length);
  }

  private static content(letter: unknown): string {
    const record = PreimageFields.record(letter, this.SIGNED_FIELDS);
    BoundedText.encode(record.conversationId, this.MAX_CONVERSATION_ID_BYTES);
    this.payload(record.payload);

    return (
      this.DOMAIN +
      CanonicalJson.serialize({
        conversationId: record.conversationId,
        kind: this.KIND,
        payload: record.payload,
        recipientIdentityId: PreimageFields.bodyCredential(
          record.recipientIdentityId,
        ),
        senderIdentityId: PreimageFields.bodyCredential(
          record.senderIdentityId,
        ),
        sentAt: PreimageFields.counter(record.sentAt),
      })
    );
  }

  /** The exact text the sender identity signs for these fields. */
  public static signingContent(
    letter: GroupMailboxControlLetterFields,
  ): string {
    return PreimageFields.guarded(InvalidGroupMailboxControlLetterError, () =>
      this.content(letter),
    );
  }

  /** Signs the draft with the sender identity and seals it to the recipient. */
  public static seal(
    senderKey: PrivateKey,
    draft: GroupMailboxControlLetterDraft,
  ): string {
    return PreimageFields.guarded(InvalidGroupMailboxControlLetterError, () => {
      const record = PreimageFields.record(draft, this.DRAFT_FIELDS);
      const payload = record.payload;
      PreimageFields.check(
        payload instanceof Uint8Array &&
          payload.length <= this.MAX_PAYLOAD_BYTES,
      );
      const letter = {
        conversationId: record.conversationId,
        payload: CanonicalBase64Url.encode(payload as Uint8Array),
        recipientIdentityId: record.recipientIdentityId,
        senderIdentityId: PreimageFields.credentialBody(
          senderKey.getPublicKey(),
        ),
        sentAt: record.sentAt,
      };
      const signature = senderKey.sign(this.content(letter));

      return this.identityKey(letter.recipientIdentityId as string)
        .encrypt(
          StrictCanonicalJson.serialize({
            ...letter,
            kind: this.KIND,
            signature: signature.valueOf(),
          }),
        )
        .valueOf();
    });
  }

  /**
   * Opens a letter sealed to this recipient key, and returns it only when the
   * expected sender identity signed it for this recipient.
   */
  public static open(
    recipientKey: PrivateKey,
    sealed: string,
    senderIdentityId: string,
  ): OpenedGroupMailboxControlLetter {
    return PreimageFields.guarded(InvalidGroupMailboxControlLetterError, () => {
      const sender = PreimageFields.bodyCredential(senderIdentityId);
      const json = this.UTF8.decode(
        recipientKey.decrypt(
          new EncryptedPayload(
            PreimageFields.text(sealed, this.MAX_SEALED_LENGTH),
          ),
        ),
      );
      const record = PreimageFields.record(StrictCanonicalJson.parse(json), [
        ...this.SIGNED_FIELDS,
        'kind',
        'signature',
      ]);
      PreimageFields.check(StrictCanonicalJson.serialize(record) === json);
      PreimageFields.literal(record.kind, this.KIND);
      PreimageFields.check(
        record.senderIdentityId === sender &&
          record.recipientIdentityId ===
            PreimageFields.credentialBody(recipientKey.getPublicKey()),
      );
      const letter = Object.fromEntries(
        this.SIGNED_FIELDS.map((field) => [field, record[field]]),
      );
      PreimageFields.verify(
        this.content(letter),
        new Signature(PreimageFields.signature(record.signature)),
        this.identityKey(sender),
      );

      return Object.freeze({
        conversationId: record.conversationId as string,
        payload: this.payload(record.payload),
        sentAt: record.sentAt as number,
      });
    });
  }
}
