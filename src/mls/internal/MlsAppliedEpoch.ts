import type { ClientState } from 'ts-mls';

import type { MlsMembershipChange } from '../MlsMembershipChange';

/** A commit an `MlsGroup` took for an epoch. */
export interface MlsAppliedEpoch {
  readonly commitId: string;
  /**
   * State before the commit, kept to switch to a competing commit while the
   * epoch is among the `RETAINED_EPOCHS` latest; then dropped.
   */
  readonly before: ClientState | undefined;
  /** The roster frontier the group had bound before the commit. */
  readonly baseline: readonly string[];
  /** The roster frontier the commit bound. */
  readonly frontier: readonly string[];
  /** What the commit changed, to judge it again against a competitor. */
  readonly change: MlsMembershipChange;
}
