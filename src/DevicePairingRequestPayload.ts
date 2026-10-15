/** A pairing request, signed by the joining device `targetCredential`. */
export type DevicePairingRequestPayload = Readonly<{
  authorizedAt: number;
  invitation: string;
  operationId: string;
  proofOfPossession: string;
  targetCredential: string;
  transportPublicKey: string;
  version: 1;
}>;
