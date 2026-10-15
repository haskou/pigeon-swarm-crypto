/** One sealed device secret entry; credentials use their PEM body form. */
export type DeviceSealedSecretPayload = Readonly<{
  authorizationRevision: number;
  generation: number;
  identityId: string;
  publisherCredential: string;
  recipientCredential: string;
  sealedSecret: string;
}>;
