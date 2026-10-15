/** The challenge a node sends before accepting one private batch. */
export type PrivateFreshnessRequestInput = Readonly<{
  batchCommitment: string;
  expectedHeadHash: string;
  expectedRevision: number;
  nonce: string;
  scopeId: string;
}>;
