/** A published commit: its id, the epoch it was made in and its bytes. */
export interface MlsCommitRecord {
  readonly id: string;
  readonly epoch: bigint;
  readonly bytes: Uint8Array;
}
