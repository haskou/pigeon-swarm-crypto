import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { ConversationDraftContent } from './ConversationDraftContent';
import { EncryptedPayload } from './EncryptedPayload';
import { InvalidConversationDraftError } from './errors/InvalidConversationDraftError';
import { BoundedText } from './internal/BoundedText';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { KeyMaterial } from './internal/KeyMaterial';
import { SymmetricKey } from './SymmetricKey';

export class ConversationDraft {
  private static readonly DRAFT_KEY_LENGTH = 32;
  private static readonly KEY_LABEL = 'pigeon/conversation-draft-key/v1';
  private static readonly MAX_CONVERSATION_ID_BYTES = 4096;
  private static readonly PAYLOAD_LABEL = 'pigeon/conversation-draft/v1';

  private static aad(draftKey: string): string {
    return `${ConversationDraft.PAYLOAD_LABEL}:${draftKey}`;
  }

  private static computeDraftKey(
    root: SymmetricKey,
    conversationId: string,
  ): string {
    const conversation = BoundedText.encode(
      conversationId,
      ConversationDraft.MAX_CONVERSATION_ID_BYTES,
    );
    const draftRoot = hkdf(
      sha256,
      KeyMaterial.of(root),
      undefined,
      Buffer.from(ConversationDraft.KEY_LABEL, 'utf8'),
      ConversationDraft.DRAFT_KEY_LENGTH,
    );

    return CanonicalBase64Url.encode(hmac(sha256, draftRoot, conversation));
  }

  private static serialize(content: string, conversationId: string): string {
    return JSON.stringify({ content, conversationId });
  }

  public static draftKey(root: SymmetricKey, conversationId: string): string {
    try {
      return this.computeDraftKey(root, conversationId);
    } catch {
      throw new InvalidConversationDraftError();
    }
  }

  public static seal(
    root: SymmetricKey,
    conversationId: string,
    content: string,
  ): string {
    try {
      if (typeof content !== 'string')
        throw new InvalidConversationDraftError();

      const aad = this.aad(this.computeDraftKey(root, conversationId));

      return root
        .encrypt(this.serialize(content, conversationId), { aad })
        .valueOf();
    } catch {
      throw new InvalidConversationDraftError();
    }
  }

  public static open(
    root: SymmetricKey,
    draftKey: string,
    encryptedPayload: string,
  ): ConversationDraftContent {
    try {
      CanonicalBase64Url.decode(draftKey, ConversationDraft.DRAFT_KEY_LENGTH);
      const json = root
        .decrypt(new EncryptedPayload(encryptedPayload), {
          aad: this.aad(draftKey),
        })
        .toString('utf8');
      const parsed = JSON.parse(json) as Record<string, unknown>;
      const { content, conversationId } = parsed;

      if (
        typeof content !== 'string' ||
        typeof conversationId !== 'string' ||
        this.serialize(content, conversationId) !== json ||
        this.computeDraftKey(root, conversationId) !== draftKey
      )
        throw new InvalidConversationDraftError();

      return Object.freeze({ content, conversationId });
    } catch {
      throw new InvalidConversationDraftError();
    }
  }
}
