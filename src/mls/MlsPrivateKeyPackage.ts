/** The private half of an MLS key package; keep it encrypted at rest. */
export interface MlsPrivateKeyPackage {
  readonly hpkePrivateKey: Uint8Array;
  readonly initPrivateKey: Uint8Array;
  readonly signaturePrivateKey: Uint8Array;
}
