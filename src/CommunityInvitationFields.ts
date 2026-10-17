/** What both invitation proofs sign: who joins which community, how. */
export type CommunityInvitationFields = Readonly<{
  communityId: string;
  identityId: string;
  invitationId: string;
  networkId: string;
}>;
