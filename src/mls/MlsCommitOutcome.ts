/** What applying a published commit did to the group. */
export type MlsCommitOutcome =
  | { kind: 'applied'; epoch: bigint }
  | { kind: 'replaced'; epoch: bigint; discardedCommitId: string }
  | {
      kind: 'ignored';
      reason: 'duplicate' | 'lost-race' | 'stale' | 'withheld';
    }
  | { kind: 'gap'; have: bigint; got: bigint }
  | { kind: 'removed' };
