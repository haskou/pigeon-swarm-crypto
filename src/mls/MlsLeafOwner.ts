/** The identity and device a leaf of an MLS group belongs to. */
export interface MlsLeafOwner {
  /** The device's Ed25519 public key as a 113-character SPKI PEM. */
  readonly deviceCredential: string;
  /** The identity's Ed25519 public key as the 60-character SPKI base64 body. */
  readonly identityId: string;
}
