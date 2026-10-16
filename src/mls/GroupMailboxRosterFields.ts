/** The roster a group conversation's MLS GroupContext carries. */
export type GroupMailboxRosterFields = Readonly<{
  adminIds: readonly string[];
  conversationId: string;
  creatorId: string;
  memberIds: readonly string[];
  name: string;
  version: number;
}>;
