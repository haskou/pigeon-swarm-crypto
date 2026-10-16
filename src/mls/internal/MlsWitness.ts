/** A commit that bound roster operations the device has not verified. */
export interface MlsWitness {
  readonly committer: string;
  readonly epoch: bigint;
  readonly frontier: readonly string[];
}
