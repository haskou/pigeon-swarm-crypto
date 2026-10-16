import {
  type ClientState,
  type GroupState,
  type IncomingMessageCallback,
  type Proposal,
  type ProcessMessageResult,
  createApplicationMessage,
  createGroup,
  decodeGroupState,
  emptyPskIndex,
  encodeGroupState,
  encodeMlsMessage,
  joinGroupWithExtensions,
  mlsExporter,
  processPrivateMessage,
} from 'ts-mls';
import { decryptSenderData } from 'ts-mls/privateMessage.js';

import type { MlsAppliedEpoch } from './internal/MlsAppliedEpoch';
import type { MlsPendingCommit } from './internal/MlsPendingCommit';
import type { MlsSentMessage } from './internal/MlsSentMessage';
import type { MlsWitness } from './internal/MlsWitness';
import type { MlsCommitOutcome } from './MlsCommitOutcome';
import type { MlsCommitOutput } from './MlsCommitOutput';
import type { MlsCommitRecord } from './MlsCommitRecord';
import type { MlsContextExtension } from './MlsContextExtension';
import type { MlsGroupLeaf } from './MlsGroupLeaf';
import type { MlsKeyPackage } from './MlsKeyPackage';
import type { MlsLeafOwner } from './MlsLeafOwner';
import type { MlsMembershipChange } from './MlsMembershipChange';
import type { MlsMembershipPolicy } from './MlsMembershipPolicy';
import type { MlsOpenedMessage } from './MlsOpenedMessage';

import { BoundedText } from '../internal/BoundedText';
import { buildMlsCommit } from './internal/MlsCommitBuilder';
import {
  RETAINED_EPOCHS,
  assertCommitterKept,
  clientConfig,
  contextOf,
  decodeMessage,
  defined,
  keyPackageOwner,
  leafAt,
  membershipChange,
  ownerOf,
  readCommit,
  rejection,
  resume,
  sameEpoch,
  welcomeSigner,
} from './internal/MlsGroupRules';
import { getMlsCiphersuite } from './internal/MlsRuntime';
import { InvalidMlsGroupError } from './InvalidMlsGroupError';
import { MlsRosterFrontier } from './MlsRosterFrontier';

/**
 * One MLS group as seen by one device, over ciphersuite
 * MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 with private handshakes.
 * Every leaf credential is an `MlsLeafCredential`; whether its identity may
 * hold a leaf is the `MlsMembershipPolicy`'s call. Every commit and welcome
 * binds the roster frontier its committer judged it at (`MlsRosterFrontier`)
 * and the group remembers the frontier of its last commit. Immutable states
 * let the device return to the state before a commit when a competing commit
 * for the same epoch wins it. Rivals rank by: whether the roster this device
 * verified still allows the commit, then the policy's reach of its frontier,
 * then the policy's priority of its change, then the lower id. A commit by a
 * member that binds roster operations this device has not verified stops the
 * group until they arrive (`waiting`). Hostile input is rejected with
 * `InvalidMlsGroupError`; policy errors pass through.
 */
export class MlsGroup {
  private static readonly decoder = new TextDecoder();
  private static readonly encoder = new TextEncoder();
  private static readonly CALL_MEDIA_LABEL = 'pigeon/call-media/v1';
  private static readonly GENERATION_LABEL = 'pigeon/group-mailbox/gen/v1';
  private static readonly MAX_CALL_ID_BYTES = 256;
  private static readonly SECRET_LENGTH = 32;

  /** Commits, by id, that bound roster operations not verified here. */
  private readonly witnesses = new Map<string, MlsWitness>();

  /**
   * The states this device left when it stepped back (`stepBack`). Taking
   * the same commit again resumes the matching one, so the sending
   * generations it used go on and members do not refuse its next messages.
   */
  private readonly resumable: ClientState[] = [];

  /**
   * The commits taken since create, join or restore, by the epoch they left.
   * Epochs are only added past the last one or replaced in place, and later
   * ones are dropped with them, so iteration runs in ascending epoch order.
   * Only the `RETAINED_EPOCHS` latest keep the state before their commit.
   */
  private readonly applied = new Map<bigint, MlsAppliedEpoch>();

  private pending: MlsPendingCommit | undefined;

  private static async rejecting<T>(work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (error) {
      throw rejection(error);
    }
  }

  /** Whether the state's own leaf names `owner`, identity and device. */
  private static ownsLeaf(state: GroupState, owner: MlsLeafOwner): boolean {
    try {
      const leaf = ownerOf(
        leafAt(state.ratchetTree, state.privatePath.leafIndex).leaf.credential,
      );

      return (
        leaf.identityId === owner.identityId &&
        leaf.deviceCredential === owner.deviceCredential
      );
    } catch {
      return false;
    }
  }

  /** Starts a group with this device alone and these context extensions. */
  public static create(
    groupId: string,
    key: MlsKeyPackage,
    policy: MlsMembershipPolicy,
    extensions: readonly MlsContextExtension[] = [],
  ): Promise<MlsGroup> {
    return MlsGroup.rejecting(async () => {
      const state = await createGroup(
        MlsGroup.encoder.encode(groupId),
        decodeMessage(key.publicBytes, 'mls_key_package').keyPackage,
        key.privatePackage,
        [...extensions],
        await getMlsCiphersuite(),
        clientConfig,
      );

      return new MlsGroup(
        groupId,
        key.owner,
        policy,
        state,
        false,
        policy.frontier(),
        undefined,
      );
    });
  }

  /**
   * Joins from a welcome for `groupId` whose GroupInfo binds one roster
   * frontier and whose tree holds only identities the policy admits there.
   */
  public static join(
    groupId: string,
    key: MlsKeyPackage,
    welcomeBytes: Uint8Array,
    policy: MlsMembershipPolicy,
  ): Promise<MlsGroup> {
    return MlsGroup.rejecting(async () => {
      const { welcome } = decodeMessage(welcomeBytes, 'mls_welcome');
      const { keyPackage } = decodeMessage(key.publicBytes, 'mls_key_package');
      const cs = await getMlsCiphersuite();
      const [state, extensions] = await joinGroupWithExtensions(
        welcome,
        keyPackage,
        key.privatePackage,
        emptyPskIndex,
        cs,
        undefined,
        undefined,
        clientConfig,
      );
      const frontiers = extensions.filter(
        ({ extensionType }) =>
          extensionType === MlsRosterFrontier.EXTENSION_TYPE,
      );

      if (
        MlsGroup.decoder.decode(state.groupContext.groupId) !== groupId ||
        frontiers.length !== 1
      )
        throw new InvalidMlsGroupError();
      const frontier = MlsRosterFrontier.decode(frontiers[0].extensionData);
      const group = new MlsGroup(
        groupId,
        key.owner,
        policy,
        state,
        false,
        frontier,
        await welcomeSigner(
          welcome,
          keyPackage,
          key.privatePackage,
          state.ratchetTree,
          cs,
        ),
      );

      if (!group.identities().every((id) => policy.admits(id, frontier)))
        throw new InvalidMlsGroupError();

      return group;
    });
  }

  /** Restores a state `serialize` gave and the frontier it had bound. */
  public static restore(
    groupId: string,
    owner: MlsLeafOwner,
    policy: MlsMembershipPolicy,
    encoded: Uint8Array,
    frontier: readonly string[],
  ): MlsGroup {
    let state: GroupState | undefined;

    try {
      state = decodeGroupState(encoded, 0)?.[0];
    } catch {
      throw new InvalidMlsGroupError();
    }

    if (
      state === undefined ||
      MlsGroup.decoder.decode(state.groupContext.groupId) !== groupId
    )
      throw new InvalidMlsGroupError();
    // A device removed before a restart must stay unable to send; its leaf
    // is blank by then, so only an active state still names its owner.
    const removed = state.groupActiveState.kind !== 'active';

    if (!removed && !MlsGroup.ownsLeaf(state, owner))
      throw new InvalidMlsGroupError();

    return new MlsGroup(
      groupId,
      owner,
      policy,
      { ...state, clientConfig },
      removed,
      frontier,
      undefined,
    );
  }

  /** The roster frontier a published commit binds, if it is one. */
  public static frontierOf(bytes: Uint8Array): readonly string[] | undefined {
    try {
      return readCommit(bytes).frontier;
    } catch {
      return undefined;
    }
  }

  /** The group an encrypted message names, undefined for anything else. */
  public static groupIdOf(bytes: Uint8Array): string | undefined {
    try {
      return MlsGroup.decoder.decode(
        decodeMessage(bytes, 'mls_private_message').privateMessage.groupId,
      );
    } catch {
      return undefined;
    }
  }

  /** The epoch an encrypted message names; rejects anything else. */
  public static epochOf(bytes: Uint8Array): bigint {
    return decodeMessage(bytes, 'mls_private_message').privateMessage.epoch;
  }

  private constructor(
    public readonly groupId: string,
    private readonly owner: MlsLeafOwner,
    private readonly policy: MlsMembershipPolicy,
    private state: ClientState,
    private removed: boolean,
    private bound: readonly string[],
    /**
     * The leaf that signed the welcome this group was joined from; undefined
     * for a group this device created or restored.
     */
    public readonly welcomer: MlsLeafOwner | undefined,
  ) {}

  /** The roster frontier the group's last commit or welcome bound. */
  public get frontier(): readonly string[] {
    return this.bound;
  }

  public get epoch(): bigint {
    return this.state.groupContext.epoch;
  }

  public get isRemoved(): boolean {
    return this.removed;
  }

  /**
   * Whether the group waits for roster operations a member's commit bound
   * and this device has not verified yet: they may demote a member whose
   * commits the group would otherwise take. Meanwhile it takes no commit and
   * makes none.
   */
  public get waiting(): boolean {
    return [...this.witnesses.values()].some(({ committer, frontier }) =>
      this.policy.withheld(committer, frontier),
    );
  }

  /** Remove proposals for every leaf `doomed` names. */
  private removals(doomed: (owner: MlsLeafOwner) => boolean): Proposal[] {
    return this.leaves()
      .filter(({ owner }) => doomed(owner))
      .map(({ index }) => ({
        proposalType: 'remove' as const,
        remove: { removed: index },
      }));
  }

  /** Commits the removal of every leaf `doomed` names; undefined if none. */
  private async removeLeaves(
    doomed: (owner: MlsLeafOwner) => boolean,
  ): Promise<MlsCommitOutput | undefined> {
    const proposals = this.removals(doomed);

    return proposals.length === 0 ? undefined : this.commit(proposals);
  }

  /** The leaf that sent a private message in an epoch this device holds. */
  private async sender(bytes: Uint8Array): Promise<MlsSentMessage> {
    const message = decodeMessage(bytes, 'mls_private_message').privateMessage;
    const epoch =
      message.epoch === this.state.groupContext.epoch
        ? {
            ratchetTree: this.state.ratchetTree,
            senderDataSecret: this.state.keySchedule.senderDataSecret,
          }
        : this.state.historicalReceiverData.get(message.epoch);

    if (epoch === undefined) throw new InvalidMlsGroupError();
    const senderData = await decryptSenderData(
      message,
      epoch.senderDataSecret,
      await getMlsCiphersuite(),
    ).catch(() => undefined);

    if (senderData === undefined) throw new InvalidMlsGroupError();

    return {
      message,
      owner: ownerOf(
        leafAt(epoch.ratchetTree, senderData.leafIndex).leaf.credential,
      ),
    };
  }

  /**
   * Switches to a competing commit for an applied epoch when it wins
   * (`wins`); a loser leaves the group as it was.
   */
  private async replace(
    record: MlsCommitRecord,
    previous: MlsAppliedEpoch,
    before: ClientState,
  ): Promise<MlsCommitOutcome> {
    const verdict = { lost: false };
    let outcome: MlsCommitOutcome;

    try {
      outcome = await this.advance(
        record,
        before,
        previous.baseline,
        (change, frontier) => {
          verdict.lost = !this.wins(record.id, { change, frontier }, previous);

          return !verdict.lost;
        },
      );
    } catch (error) {
      if (verdict.lost) return { kind: 'ignored', reason: 'lost-race' };
      throw error;
    }

    if (outcome.kind !== 'applied') return outcome;
    for (const epoch of [...this.applied.keys()])
      if (epoch > record.epoch) this.applied.delete(epoch);

    return {
      ...outcome,
      discardedCommitId: previous.commitId,
      kind: 'replaced',
    };
  }

  /**
   * Whether a commit wins its epoch over the one the group applied. Each
   * ranks by its own key: whether the latest roster this device verified,
   * which holds both their frontiers, still allows it, then how much of the
   * roster history it binds, then the rank the policy gives its change
   * (`MlsMembershipPolicy.priority`), then the lower id. A member removed
   * by one cannot win the epoch back by binding a frontier that leaves its
   * removal out, nor, where the policy ranks a removal above the removed
   * member's commits, by grinding a lower id; a total order converges on
   * the same winner whatever order any number of rivals arrive in.
   */
  private wins(
    commitId: string,
    incoming: { change: MlsMembershipChange; frontier: readonly string[] },
    previous: MlsAppliedEpoch,
  ): boolean {
    const latest = this.policy.frontier();
    const stands = this.permits(incoming.change, latest, latest);

    if (stands !== this.permits(previous.change, latest, latest)) return stands;
    const reach = this.policy.reach(incoming.frontier);
    const held = this.policy.reach(previous.frontier);

    if (reach !== held) return reach > held;
    const rank = this.policy.priority(incoming.change);
    const heldRank = this.policy.priority(previous.change);

    return rank === heldRank ? commitId < previous.commitId : rank > heldRank;
  }

  /**
   * Whether the roster at `frontier` admits every identity the change adds
   * and lets its committer make it, stepping from `baseline`.
   */
  private permits(
    change: MlsMembershipChange,
    frontier: readonly string[],
    baseline: readonly string[],
  ): boolean {
    return (
      change.added.every((id) => this.policy.admits(id, frontier)) &&
      this.policy.allows(change, { baseline, frontier })
    );
  }

  /**
   * Accepts a commit only when it comes from a member's leaf whose
   * credential verifies and `settle` accepts the change it makes to
   * membership; `settle` learns the committer's leaf index with the change.
   * A standalone proposal is never applied, so a commit can only carry its
   * committer's proposals by value.
   */
  private judge(
    from: ClientState,
    settle: (change: MlsMembershipChange, committerLeaf: number) => boolean,
  ): IncomingMessageCallback {
    return (incoming) => {
      if (incoming.kind !== 'commit') return 'reject';
      try {
        const committer = defined(incoming.senderLeafIndex);

        return settle(
          membershipChange(
            from,
            committer,
            incoming.proposals.map(({ proposal }) => proposal),
          ),
          committer,
        )
          ? 'accept'
          : 'reject';
      } catch {
        return 'reject';
      }
    };
  }

  /**
   * Keeps the commit as a witness when it proves roster operations this
   * device has not verified, and tells whether the group now waits.
   */
  private witness(
    record: MlsCommitRecord,
    committer: string,
    frontier: readonly string[],
  ): boolean {
    if (this.policy.withheld(committer, frontier))
      this.witnesses.set(record.id, {
        committer,
        epoch: record.epoch,
        frontier,
      });

    return this.waiting;
  }

  /**
   * Steps back to before the first commit adding leaves that the group took
   * in or after the epoch of a witness it waits on, and after this device's
   * own last commit, dropping it and every later one: those leaves may rest
   * on rights the withheld operations revoke. The state it returns to is one
   * the node could have kept this device in by withholding those commits;
   * the node cannot undo a commit this device made, so those always stand.
   * Commits that only remove or update are not stepped back from, so they
   * hold without such an add before them. The states it leaves are kept for
   * `resume`.
   */
  private stepBack(): void {
    const since = [...this.witnesses.values()]
      .filter(({ committer, frontier }) =>
        this.policy.withheld(committer, frontier),
      )
      .reduce(
        (earliest, { epoch }) => (epoch < earliest ? epoch : earliest),
        this.state.groupContext.epoch,
      );
    const taken = [...this.applied.entries()];
    const ownLast = taken
      .map(
        ([, { change }]) =>
          change.committer === this.owner.identityId &&
          change.committerDevice === this.owner.deviceCredential,
      )
      .lastIndexOf(true);
    const first = taken
      .slice(ownLast + 1)
      .find(([epoch, { change }]) => epoch >= since && change.added.length > 0);

    if (!first) return;
    const [from, { baseline, before }] = first;

    this.resumable.push(
      this.state,
      ...taken
        .filter(([epoch]) => epoch > from)
        .map(([, left]) => defined(left.before)),
    );
    this.state = defined(before);
    this.bound = baseline;
    for (const [epoch] of taken) if (epoch >= from) this.applied.delete(epoch);
  }

  /**
   * The commit's authenticated data is the frontier it binds; its sender's
   * leaf signs it, so neither the node nor another member can change it.
   * The roster at that frontier must admit every identity the commit adds
   * and let its committer make the change, stepping from `baseline`, and
   * `contest` must let it take the epoch. While the group waits (`witness`)
   * it takes nothing and steps back from adds (`stepBack`), without
   * throwing. The commit's update path replaces the committer's leaf only
   * after the judgement, so the new leaf must verify as the same identity
   * and device.
   */
  private async advance(
    record: MlsCommitRecord,
    from: ClientState,
    baseline: readonly string[],
    contest: (
      change: MlsMembershipChange,
      frontier: readonly string[],
    ) => boolean,
  ): Promise<MlsCommitOutcome> {
    const { frontier, message } = readCommit(record.bytes);

    if (message.epoch !== record.epoch) throw new InvalidMlsGroupError();
    const judged: { change?: MlsMembershipChange; leaf?: number } = {};
    const result = await processPrivateMessage(
      from,
      message,
      emptyPskIndex,
      await getMlsCiphersuite(),
      this.judge(from, (change, committerLeaf) => {
        if (this.witness(record, change.committer, frontier)) return false;
        judged.change = change;
        judged.leaf = committerLeaf;

        return (
          this.permits(change, frontier, baseline) && contest(change, frontier)
        );
      }),
    );

    if (this.waiting) {
      this.stepBack();

      return { kind: 'ignored', reason: 'withheld' };
    }
    const { change, leaf } = judged;

    if (
      result.kind !== 'newState' ||
      result.actionTaken !== 'accept' ||
      change === undefined ||
      leaf === undefined
    )
      throw new InvalidMlsGroupError();
    assertCommitterKept(result.newState.ratchetTree, leaf, change);
    this.witnesses.clear();
    this.take(record.epoch, {
      baseline,
      before: from,
      change,
      commitId: record.id,
      frontier,
    });
    this.state = resume(this.resumable, result.newState);
    this.bound = frontier;

    if (result.newState.groupActiveState.kind !== 'active') {
      this.removed = true;

      return { kind: 'removed' };
    }

    return { epoch: result.newState.groupContext.epoch, kind: 'applied' };
  }

  private async commit(proposals: Proposal[]): Promise<MlsCommitOutput> {
    this.assertActive();

    if (this.waiting) throw new InvalidMlsGroupError();
    const frontier = this.policy.frontier();
    const change = membershipChange(
      this.state,
      this.state.privatePath.leafIndex,
      proposals,
    );

    if (!this.policy.allows(change, { baseline: this.bound, frontier }))
      throw new InvalidMlsGroupError();
    const binding = MlsRosterFrontier.encode(frontier);
    const result = await buildMlsCommit(
      this.state,
      proposals,
      binding,
      [
        {
          extensionData: binding,
          extensionType: MlsRosterFrontier.EXTENSION_TYPE,
        },
      ],
      await getMlsCiphersuite(),
    );
    const epoch = this.state.groupContext.epoch;

    // The caller publishes the commit and only then calls `confirm`.
    this.pending = {
      before: this.state,
      change,
      epoch,
      frontier,
      state: result.newState,
    };

    return {
      commit: encodeMlsMessage(result.commit),
      epoch,
      welcome:
        result.welcome &&
        encodeMlsMessage({
          version: 'mls10',
          welcome: result.welcome,
          wireformat: 'mls_welcome',
        }),
    };
  }

  private assertActive(): void {
    if (this.removed) throw new InvalidMlsGroupError();
  }

  /**
   * Keeps the commit taken for `epoch` and drops the state before every
   * commit more than `RETAINED_EPOCHS` epochs behind the epoch it leads to.
   */
  private take(epoch: bigint, taken: MlsAppliedEpoch): void {
    const oldest = epoch + 1n - BigInt(RETAINED_EPOCHS);

    this.applied.set(epoch, taken);
    for (const [held, entry] of this.applied)
      if (held < oldest && entry.before !== undefined)
        this.applied.set(held, { ...entry, before: undefined });
  }

  private exporter(label: string, context: Uint8Array): Promise<Uint8Array> {
    return MlsGroup.rejecting(async () => {
      this.assertActive();

      return mlsExporter(
        this.state.keySchedule.exporterSecret,
        label,
        context,
        MlsGroup.SECRET_LENGTH,
        await getMlsCiphersuite(),
      );
    });
  }

  public serialize(): Uint8Array {
    return encodeGroupState(this.state);
  }

  /** Identities that currently hold at least one leaf. */
  public identities(): string[] {
    return [...new Set(this.leaves().map(({ owner }) => owner.identityId))];
  }

  /**
   * What each commit the group took since this device created, joined or
   * restored it changed, oldest first.
   */
  public changes(): MlsMembershipChange[] {
    return [...this.applied.values()].map(({ change }) => change);
  }

  /**
   * Identities holding a leaf that one of their own commits or updates
   * wrote. A leaf only ever added still carries the key package its adder
   * chose, so an identity added by the commit a welcome came from is never
   * among them.
   */
  public committedIdentities(): string[] {
    return [
      ...new Set(
        this.state.ratchetTree.flatMap((node) =>
          node?.nodeType === 'leaf' &&
          node.leaf.leafNodeSource !== 'key_package'
            ? [ownerOf(node.leaf.credential).identityId]
            : [],
        ),
      ),
    ];
  }

  /** Every leaf in the tree, by leaf index. */
  public leaves(): MlsGroupLeaf[] {
    return this.state.ratchetTree.flatMap((node, treeIndex) =>
      node?.nodeType === 'leaf'
        ? [
            {
              index: treeIndex / 2,
              owner: ownerOf(node.leaf.credential),
              signaturePublicKey: node.leaf.signaturePublicKey,
            },
          ]
        : [],
    );
  }

  /** The current GroupContext extensions, which every member agrees on. */
  public context(): MlsContextExtension[] {
    return contextOf(this.state.groupContext.extensions);
  }

  /** Whether every leaf lists the extension type in its capabilities. */
  public supports(extensionType: number): boolean {
    return this.state.ratchetTree.every(
      (node) =>
        node?.nodeType !== 'leaf' ||
        node.leaf.capabilities.extensions.includes(extensionType),
    );
  }

  /** Adds a leaf for each key package the policy admits at its frontier. */
  public add(keyPackages: readonly Uint8Array[]): Promise<MlsCommitOutput> {
    return MlsGroup.rejecting(() => {
      const packages = keyPackages.map(
        (bytes) => decodeMessage(bytes, 'mls_key_package').keyPackage,
      );
      const frontier = this.policy.frontier();

      if (
        !packages.every((keyPackage) =>
          this.policy.admits(keyPackageOwner(keyPackage).identityId, frontier),
        )
      )
        throw new InvalidMlsGroupError();

      return this.commit(
        packages.map((keyPackage) => ({
          add: { keyPackage },
          proposalType: 'add' as const,
        })),
      );
    });
  }

  /**
   * Replaces the GroupContext extensions and, in the same commit, removes
   * every leaf of the identities in `removed`.
   */
  public changeContext(
    extensions: readonly MlsContextExtension[],
    removed: readonly string[] = [],
  ): Promise<MlsCommitOutput> {
    return MlsGroup.rejecting(() =>
      this.commit([
        {
          groupContextExtensions: { extensions: [...extensions] },
          proposalType: 'group_context_extensions' as const,
        },
        ...this.removals(({ identityId }) => removed.includes(identityId)),
      ]),
    );
  }

  /** Removes all leaves of the identities; undefined when none remain. */
  public removeIdentities(
    identityIds: readonly string[],
  ): Promise<MlsCommitOutput | undefined> {
    return MlsGroup.rejecting(() =>
      this.removeLeaves(({ identityId }) => identityIds.includes(identityId)),
    );
  }

  /**
   * Removes the leaves of these devices of one identity; undefined when
   * none holds a leaf.
   */
  public removeDevices(
    identityId: string,
    deviceCredentials: readonly string[],
  ): Promise<MlsCommitOutput | undefined> {
    return MlsGroup.rejecting(() =>
      this.removeLeaves(
        (owner) =>
          owner.identityId === identityId &&
          deviceCredentials.includes(owner.deviceCredential),
      ),
    );
  }

  /** Rotates this device's leaf key. */
  public update(): Promise<MlsCommitOutput> {
    return MlsGroup.rejecting(() => this.commit([]));
  }

  public encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    return MlsGroup.rejecting(async () => {
      this.assertActive();
      const result = await createApplicationMessage(
        this.state,
        plaintext,
        await getMlsCiphersuite(),
      );

      this.state = result.newState;

      return encodeMlsMessage({
        privateMessage: result.privateMessage,
        version: 'mls10',
        wireformat: 'mls_private_message',
      });
    });
  }

  public async decrypt(bytes: Uint8Array): Promise<Uint8Array> {
    return (await this.open(bytes)).plaintext;
  }

  /**
   * Names the leaf that sent a private message (application or commit) in
   * an epoch this device still holds. Proves only that the sender held that
   * epoch's sender-data secret; signatures are checked when it is processed.
   */
  public authenticate(bytes: Uint8Array): Promise<MlsLeafOwner> {
    return MlsGroup.rejecting(async () => (await this.sender(bytes)).owner);
  }

  /**
   * Decrypts an application message and names its sender: the leaf whose
   * signature ts-mls verified, in the epoch it was sent.
   */
  public open(bytes: Uint8Array): Promise<MlsOpenedMessage> {
    return MlsGroup.rejecting(async () => {
      const { message, owner } = await this.sender(bytes);

      if (message.contentType !== 'application')
        throw new InvalidMlsGroupError();
      // An application message always yields its plaintext.
      const result = (await processPrivateMessage(
        this.state,
        message,
        emptyPskIndex,
        await getMlsCiphersuite(),
      )) as Extract<ProcessMessageResult, { kind: 'applicationMessage' }>;

      this.state = result.newState;

      return { plaintext: result.message, sender: owner };
    });
  }

  /**
   * The 32-byte media key of call `callId` in the current epoch (RFC 9420
   * §8.5 exporter, label `pigeon/call-media/v1`, context the UTF-8 call id
   * of at most 256 bytes).
   */
  public callMediaKey(callId: string): Promise<Uint8Array> {
    let context: Uint8Array;

    try {
      context = BoundedText.encode(callId, MlsGroup.MAX_CALL_ID_BYTES);
    } catch {
      return Promise.reject(new InvalidMlsGroupError());
    }

    return this.exporter(MlsGroup.CALL_MEDIA_LABEL, context);
  }

  /**
   * The 32-byte group mailbox generation secret of the current epoch (RFC
   * 9420 §8.5 exporter, label `pigeon/group-mailbox/gen/v1`, empty context).
   */
  public groupMailboxGenerationSecret(): Promise<Uint8Array> {
    return this.exporter(MlsGroup.GENERATION_LABEL, new Uint8Array());
  }

  /**
   * Takes a published commit for its epoch: applies it, switches to it when
   * it beats the commit taken for that epoch, or says why it does neither.
   */
  public applyCommit(record: MlsCommitRecord): Promise<MlsCommitOutcome> {
    return MlsGroup.rejecting(async () => {
      if (this.removed) return { kind: 'removed' };
      const previous = this.applied.get(record.epoch);
      const current = this.state.groupContext.epoch;

      if (record.epoch > current)
        return { got: record.epoch, have: current, kind: 'gap' };

      if (previous?.commitId === record.id)
        return { kind: 'ignored', reason: 'duplicate' };

      if (record.epoch === current)
        return this.advance(record, this.state, this.bound, () => true);

      return previous?.before === undefined
        ? { kind: 'ignored', reason: 'stale' }
        : this.replace(record, previous, previous.before);
    });
  }

  /**
   * The encoded state the pending commit leads to and the frontier it
   * binds, so both can be kept aside before it is published.
   */
  public pendingState(): { frontier: readonly string[]; state: Uint8Array } {
    if (this.pending === undefined) throw new InvalidMlsGroupError();

    return {
      frontier: this.pending.frontier,
      state: encodeGroupState(this.pending.state),
    };
  }

  /**
   * Adopts the pending commit once the node has accepted its record. Pass
   * the record id the node assigned. Refused, and dropped, once the group
   * left the epoch and branch the commit was built on, e.g. because a rival
   * replaced an earlier commit.
   */
  public confirm(commitId: string): MlsCommitOutcome {
    const pending = this.pending;

    if (pending === undefined) throw new InvalidMlsGroupError();
    this.pending = undefined;

    if (!sameEpoch(this.state, pending.before))
      throw new InvalidMlsGroupError();
    this.witnesses.clear();
    this.take(pending.epoch, {
      baseline: this.bound,
      before: pending.before,
      change: pending.change,
      commitId,
      frontier: pending.frontier,
    });
    this.state = pending.state;
    this.bound = pending.frontier;

    return { epoch: this.state.groupContext.epoch, kind: 'applied' };
  }

  /** Drops the pending commit, e.g. because another commit won the epoch. */
  public abandon(): void {
    this.pending = undefined;
  }
}
