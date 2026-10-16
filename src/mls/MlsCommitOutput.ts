/** A commit this device made, with the welcome for any added members. */
export interface MlsCommitOutput {
  readonly epoch: bigint;
  readonly commit: Uint8Array;
  readonly welcome?: Uint8Array;
}
