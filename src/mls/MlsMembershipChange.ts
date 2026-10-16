import type { MlsContextExtension } from './MlsContextExtension';

/** What a commit does to an MLS group, as the membership policy judges it. */
export interface MlsMembershipChange {
  readonly committer: string;
  readonly committerDevice: string;
  readonly added: readonly string[];
  readonly removed: readonly string[];
  readonly context: readonly MlsContextExtension[];
  /** The identity of every leaf in the tree the commit starts from. */
  readonly holders: readonly string[];
  /** The GroupContext extensions the commit proposes, when it proposes any. */
  readonly proposedContext?: readonly MlsContextExtension[];
}
