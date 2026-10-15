/** The values both devices compare before a pairing request is approved. */
export type DevicePairingVerificationInput = Readonly<{
  operationId: string;
  pairingId: string;
  targetCredential: string;
  transportPublicKey: string;
}>;
