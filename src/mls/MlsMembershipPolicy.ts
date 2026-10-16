import type { MlsMembershipChange } from './MlsMembershipChange';

/**
 * The application's membership rules an `MlsGroup` enforces. A frontier is
 * the sorted list of roster-log head digests a commit is bound to.
 */
export interface MlsMembershipPolicy {
  /** The roster frontier this device has verified. */
  frontier(): readonly string[];
  /** Whether the identity may hold a leaf at the given frontier. */
  admits(identityId: string, frontier: readonly string[]): boolean;
  /** How far a frontier reaches; a further one wins a commit race. */
  reach(frontier: readonly string[]): number;
  /** How a change ranks against a rival commit at the same reach. */
  priority(change: MlsMembershipChange): number;
  /** Whether the change is allowed between the baseline and the frontier. */
  allows(
    change: MlsMembershipChange,
    order: { baseline: readonly string[]; frontier: readonly string[] },
  ): boolean;
  /** Whether a commit bound to the frontier waits for roster operations. */
  withheld(committer: string, frontier: readonly string[]): boolean;
}
