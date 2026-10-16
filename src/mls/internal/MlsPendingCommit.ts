import type { ClientState } from 'ts-mls';

import type { MlsMembershipChange } from '../MlsMembershipChange';

/** A commit an `MlsGroup` made and waits to see accepted. */
export interface MlsPendingCommit {
  readonly before: ClientState;
  readonly change: MlsMembershipChange;
  readonly epoch: bigint;
  readonly frontier: readonly string[];
  readonly state: ClientState;
}
