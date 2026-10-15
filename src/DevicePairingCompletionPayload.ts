/** A pairing completion, signed by the inviting device `authorCredential`. */
export type DevicePairingCompletionPayload = Readonly<{
  authorCredential: string;
  encryptedMaterial: string;
  epoch: string;
  identityId: string;
  operationId: string;
  pairingId: string;
  revision: number;
  version: 1;
}>;
