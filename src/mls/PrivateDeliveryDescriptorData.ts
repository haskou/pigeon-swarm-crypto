export interface PrivateDeliveryDescriptorData {
  readonly authorizationRevision: number;
  readonly mailboxId: string;
  readonly maxCiphertextExpiresAt: number;
  readonly recipientPublicKey: string;
  readonly validFrom: number;
  readonly version: 1;
  readonly writeValidUntil: number;
}
