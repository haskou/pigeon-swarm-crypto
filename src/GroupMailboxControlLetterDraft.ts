/** What a sender seals: a control record for one recipient identity. */
export interface GroupMailboxControlLetterDraft {
  readonly conversationId: string;
  readonly payload: Uint8Array;
  readonly recipientIdentityId: string;
  readonly sentAt: number;
}
