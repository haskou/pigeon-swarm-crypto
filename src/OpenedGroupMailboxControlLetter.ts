/** A letter the recipient opened and the expected sender signed. */
export interface OpenedGroupMailboxControlLetter {
  readonly conversationId: string;
  readonly payload: Uint8Array;
  readonly sentAt: number;
}
