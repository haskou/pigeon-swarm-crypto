/** The signed fields of a letter, with the payload as base64url. */
export interface GroupMailboxControlLetterFields {
  readonly conversationId: string;
  readonly payload: string;
  readonly recipientIdentityId: string;
  readonly senderIdentityId: string;
  readonly sentAt: number;
}
