/** A pairing invitation, signed by the inviting device `authorCredential`. */
export type DevicePairingInvitationPayload = Readonly<{
  authorCredential: string;
  epoch: string;
  expiresAt: number;
  identityId: string;
  pairingId: string;
  revision: number;
  version: 1;
}>;
