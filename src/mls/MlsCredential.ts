export interface MlsCredential {
  readonly identity: Uint8Array;
  readonly signaturePublicKey: Uint8Array;
}
