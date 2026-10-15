import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidMailboxKeyError } from './errors/InvalidMailboxKeyError';
import { BoundedText } from './internal/BoundedText';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { KeyMaterial } from './internal/KeyMaterial';
import { MailboxInboxKeys } from './MailboxInboxKeys';
import { SymmetricKey } from './SymmetricKey';

export class MailboxKeySchedule {
  private static readonly CONTACT_PRESENCE_LABEL = 'pigeon/contact-presence/v1';
  private static readonly ENVELOPE_LABEL = 'pigeon/mailbox/envelope/v1';
  private static readonly ID_LABEL = 'pigeon/mailbox/id/v1';
  private static readonly KEY_LENGTH = 32;
  private static readonly MAX_EPOCH = 4294967295;
  private static readonly MAX_RECIPIENT_BYTES = 4096;
  private static readonly POST_LABEL = 'pigeon/mailbox/post/v1';

  private static expand(
    secret: Uint8Array,
    label: string,
    context: Uint8Array,
  ): Uint8Array {
    return hkdf(
      sha256,
      secret,
      undefined,
      Buffer.concat([Buffer.from(label, 'utf8'), context]),
      MailboxKeySchedule.KEY_LENGTH,
    );
  }

  private static schedule(
    secret: Uint8Array,
    recipientIdentityId: string,
    epoch: number,
  ): MailboxInboxKeys {
    const recipient = BoundedText.encode(
      recipientIdentityId,
      MailboxKeySchedule.MAX_RECIPIENT_BYTES,
    );

    if (
      !Number.isSafeInteger(epoch) ||
      epoch < 0 ||
      epoch > MailboxKeySchedule.MAX_EPOCH
    )
      throw new InvalidMailboxKeyError();
    const epochBytes = Buffer.alloc(4);
    epochBytes.writeUInt32BE(epoch);
    const context = Buffer.concat([recipient, epochBytes]);

    return Object.freeze({
      envelopeKey: this.expand(
        secret,
        MailboxKeySchedule.ENVELOPE_LABEL,
        context,
      ),
      mailboxId: CanonicalBase64Url.encode(
        this.expand(secret, MailboxKeySchedule.ID_LABEL, context),
      ),
      postToken: CanonicalBase64Url.encode(
        this.expand(secret, MailboxKeySchedule.POST_LABEL, context),
      ),
    });
  }

  public static derive(
    sharedSecret: SymmetricKey,
    recipientIdentityId: string,
    epoch: number,
  ): MailboxInboxKeys {
    try {
      return this.schedule(
        KeyMaterial.of(sharedSecret),
        recipientIdentityId,
        epoch,
      );
    } catch {
      throw new InvalidMailboxKeyError();
    }
  }

  public static contactPresence(
    conversationKey: SymmetricKey,
    recipientIdentityId: string,
  ): MailboxInboxKeys {
    try {
      const secret = hkdf(
        sha256,
        KeyMaterial.of(conversationKey),
        undefined,
        Buffer.from(MailboxKeySchedule.CONTACT_PRESENCE_LABEL, 'utf8'),
        MailboxKeySchedule.KEY_LENGTH,
      );

      return this.schedule(secret, recipientIdentityId, 0);
    } catch {
      throw new InvalidMailboxKeyError();
    }
  }
}
