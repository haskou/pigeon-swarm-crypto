/** The keychain version fields its owner identity key signs. */
export type KeychainSignaturePayload = Readonly<{
  encryptedPayload: string;
  ownerIdentityId: string;
  previousKeychainExternalIdentifier?: string;
  timestamp: number;
  version: number;
}>;
