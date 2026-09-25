import { sha256 } from '@noble/hashes/sha2.js';
import {
  ClientConfig,
  ClientState,
  createApplicationMessage,
  createCommit,
  createGroup,
  defaultKeyPackageEqualityConfig,
  defaultKeyRetentionConfig,
  defaultLifetimeConfig,
  defaultPaddingConfig,
  emptyPskIndex,
  joinGroup,
  processMessage,
  zeroOutUint8Array,
} from 'ts-mls';

import { UserRootKey } from '../UserRootKey';
import { DeliveryBase64Url } from './internal/DeliveryBase64Url';
import {
  decodeMessage,
  decodeState,
  encodeGroupContext,
  encodeMessage,
  encodeState,
} from './internal/MlsCodec';
import { MLS_JOIN_PACKAGE_USE } from './internal/MlsJoinPackageUse';
import {
  acceptsMlsMemberCount,
  MAX_MLS_APPLICATION_BYTES,
  requireMlsWelcome,
  validateMlsCredential,
} from './internal/MlsProtocolPolicy';
import { getMlsCiphersuite } from './internal/MlsRuntime';
import { MAX_PRIVATE_DELIVERY_BUCKET_BYTES } from './internal/PrivateDeliveryPolicy';
import { InvalidMlsFrameError } from './InvalidMlsFrameError';
import { InvalidMlsStateError } from './InvalidMlsStateError';
import { MlsApplicationFrame } from './MlsApplicationFrame';
import { MlsCommitFrame } from './MlsCommitFrame';
import { MlsCredentialVerifier } from './MlsCredentialVerifier';
import { MlsJoinPackage } from './MlsJoinPackage';
import { MlsWelcomeFrame } from './MlsWelcomeFrame';
import { PrivateDeliveryEnvelope } from './PrivateDeliveryEnvelope';
import { PrivateDeliveryFrame } from './PrivateDeliveryFrame';
import { ProtectedMlsGroupState } from './ProtectedMlsGroupState';

const createConfig = (verify: MlsCredentialVerifier): ClientConfig => ({
  authService: {
    async validateCredential(credential, signaturePublicKey) {
      return validateMlsCredential(credential, signaturePublicKey, verify);
    },
  },
  keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
  keyRetentionConfig: defaultKeyRetentionConfig,
  lifetimeConfig: defaultLifetimeConfig,
  paddingConfig: defaultPaddingConfig,
});

const MAX_GROUP_ID_BYTES = 1024;
const MAX_GROUP_MEMBERS = 128;
const MAX_PUBLIC_PACKAGE_BYTES = 65536;
const MAX_IDENTITY_BYTES = 1024;

const memberCount = (state: ClientState): number =>
  state.ratchetTree.filter((node) => node?.nodeType === 'leaf').length;

const stateCommitment = (state: ClientState): string => {
  const bytes = encodeState(state);

  try {
    return DeliveryBase64Url.encode(sha256(bytes));
  } finally {
    bytes.fill(0);
  }
};

const eraseConsumed = (consumed: Uint8Array[]): void => {
  consumed.forEach(zeroOutUint8Array);
};

const identityKey = (identity: Uint8Array): string => {
  let key = '';
  for (const byte of identity) key += String.fromCharCode(byte);

  return key;
};

const requirePrivateDeliveryCapacity = (
  kind: 'application' | 'commit' | 'welcome',
  bytes: Uint8Array,
): void => {
  try {
    const frame = PrivateDeliveryFrame[kind](bytes);
    const plaintext = PrivateDeliveryEnvelope.framePlaintext(
      frame,
      MAX_PRIVATE_DELIVERY_BUCKET_BYTES,
    );
    plaintext.fill(0);
  } catch {
    throw new InvalidMlsStateError();
  }
};

export class MlsGroupSession {
  #consumed = false;

  readonly #state: ClientState;

  #transitioning = false;

  readonly #verify: MlsCredentialVerifier;

  private static decodeAndVerifyPackages(
    packages: Uint8Array[],
    verify: MlsCredentialVerifier,
  ) {
    return packages.map(async (bytes) => {
      try {
        if (
          !(bytes instanceof Uint8Array) ||
          bytes.length === 0 ||
          bytes.length > MAX_PUBLIC_PACKAGE_BYTES
        ) {
          throw new InvalidMlsStateError();
        }
        const keyPackage = MlsJoinPackage.publicPackageFromBytes(bytes);
        const credential = keyPackage.leafNode.credential;

        if (
          !(await validateMlsCredential(
            credential,
            keyPackage.leafNode.signaturePublicKey,
            verify,
          ))
        ) {
          throw new InvalidMlsStateError();
        }

        return keyPackage;
      } catch {
        throw new InvalidMlsStateError();
      }
    });
  }

  public static async create(
    groupId: Uint8Array,
    founder: MlsJoinPackage,
    verify: MlsCredentialVerifier,
  ): Promise<MlsGroupSession> {
    if (
      !(groupId instanceof Uint8Array) ||
      groupId.length === 0 ||
      groupId.length > MAX_GROUP_ID_BYTES ||
      typeof verify !== 'function'
    ) {
      throw new InvalidMlsStateError();
    }

    const state = await founder[MLS_JOIN_PACKAGE_USE](
      async (publicPackage, privatePackage) => {
        if (
          !(await validateMlsCredential(
            publicPackage.leafNode.credential,
            publicPackage.leafNode.signaturePublicKey,
            verify,
          ))
        ) {
          throw new InvalidMlsStateError();
        }
        const suite = await getMlsCiphersuite();

        return createGroup(
          new Uint8Array(groupId),
          publicPackage,
          privatePackage,
          [],
          suite,
          createConfig(verify),
        );
      },
    );

    return new MlsGroupSession(state, verify);
  }

  public static async join(
    welcome: MlsWelcomeFrame,
    joinPackage: MlsJoinPackage,
    verify: MlsCredentialVerifier,
  ): Promise<MlsGroupSession> {
    try {
      const message = decodeMessage(welcome.payloadBytes());

      if (message.wireformat !== 'mls_welcome') {
        throw new InvalidMlsFrameError();
      }
      const suite = await getMlsCiphersuite();
      const state = await joinPackage[MLS_JOIN_PACKAGE_USE](
        (publicPackage, privatePackage) =>
          joinGroup(
            message.welcome,
            publicPackage,
            privatePackage,
            emptyPskIndex,
            suite,
            undefined,
            undefined,
            createConfig(verify),
          ),
      );

      return new MlsGroupSession(state, verify);
    } catch {
      throw new InvalidMlsFrameError();
    }
  }

  public static restore(
    protectedState: ProtectedMlsGroupState,
    rootKey: UserRootKey,
    verify: MlsCredentialVerifier,
    expectedEpoch: bigint,
    expectedStateCommitment: string,
  ): MlsGroupSession {
    const bytes = protectedState.unlock(rootKey);

    try {
      const decoded = decodeState(bytes);
      const owned = decodeState(encodeState(decoded));

      try {
        DeliveryBase64Url.decode(expectedStateCommitment, 32).fill(0);
      } catch {
        throw new InvalidMlsStateError();
      }

      if (
        owned.groupContext.epoch !== expectedEpoch ||
        stateCommitment({ ...owned, clientConfig: createConfig(verify) }) !==
          expectedStateCommitment
      ) {
        throw new InvalidMlsStateError();
      }

      return new MlsGroupSession(
        { ...owned, clientConfig: createConfig(verify) },
        verify,
      );
    } finally {
      bytes.fill(0);
    }
  }

  private constructor(state: ClientState, verify: MlsCredentialVerifier) {
    if (
      !(state.groupContext.groupId instanceof Uint8Array) ||
      state.groupContext.groupId.length === 0 ||
      state.groupContext.groupId.length > MAX_GROUP_ID_BYTES ||
      memberCount(state) > MAX_GROUP_MEMBERS
    ) {
      throw new InvalidMlsStateError();
    }
    this.#state = state;
    this.#verify = verify;
  }

  private ensureAvailable(): void {
    if (this.#consumed || this.#transitioning) {
      throw new InvalidMlsStateError();
    }
  }

  private async transition<T>(
    operation: () => Promise<{
      readonly consumed: Uint8Array[];
      readonly value: T;
    }>,
  ): Promise<T> {
    this.ensureAvailable();
    this.#transitioning = true;

    try {
      const result = await operation();
      this.#consumed = true;
      eraseConsumed(result.consumed);

      return result.value;
    } finally {
      this.#transitioning = false;
    }
  }

  private async process(
    bytes: Uint8Array,
    expectedContentType: 'application' | 'commit',
  ) {
    try {
      const message = decodeMessage(bytes);

      if (
        message.wireformat !== 'mls_private_message' &&
        message.wireformat !== 'mls_public_message'
      ) {
        throw new InvalidMlsFrameError();
      }
      const contentType =
        message.wireformat === 'mls_private_message'
          ? message.privateMessage.contentType
          : message.publicMessage.content.contentType;

      if (contentType !== expectedContentType) {
        throw new InvalidMlsFrameError();
      }
      const suite = await getMlsCiphersuite();
      let rejectedByMemberLimit = false;
      const result = await processMessage(
        message,
        this.#state,
        emptyPskIndex,
        (incoming) => {
          rejectedByMemberLimit = !acceptsMlsMemberCount(
            memberCount(this.#state),
            incoming,
            MAX_GROUP_MEMBERS,
          );

          return rejectedByMemberLimit ? 'reject' : 'accept';
        },
        suite,
      );

      if (rejectedByMemberLimit) {
        throw new InvalidMlsFrameError();
      }

      return result;
    } catch {
      throw new InvalidMlsFrameError();
    }
  }

  public get epoch(): bigint {
    this.ensureAvailable();

    return this.#state.groupContext.epoch;
  }

  public get active(): boolean {
    this.ensureAvailable();

    return this.#state.groupActiveState.kind === 'active';
  }

  public get contextHash(): string {
    this.ensureAvailable();

    return DeliveryBase64Url.encode(
      sha256(encodeGroupContext(this.#state.groupContext)),
    );
  }

  public get stateCommitment(): string {
    this.ensureAvailable();

    return stateCommitment(this.#state);
  }

  public protectState(rootKey: UserRootKey): ProtectedMlsGroupState {
    this.ensureAvailable();
    const state = encodeState(this.#state);

    try {
      return ProtectedMlsGroupState.protect(state, rootKey);
    } finally {
      state.fill(0);
    }
  }

  public async addMembers(publicPackages: Uint8Array[]): Promise<{
    readonly session: MlsGroupSession;
    readonly commit: MlsCommitFrame;
    readonly welcome: MlsWelcomeFrame;
  }> {
    return this.transition(async () => {
      const currentMemberCount = memberCount(this.#state);

      if (
        publicPackages.length === 0 ||
        publicPackages.length > MAX_GROUP_MEMBERS - currentMemberCount
      ) {
        throw new InvalidMlsStateError();
      }
      const packages = MlsGroupSession.decodeAndVerifyPackages(
        publicPackages,
        this.#verify,
      );
      const verifiedPackages = await Promise.all(packages);
      const suite = await getMlsCiphersuite();
      const result = await createCommit(
        { cipherSuite: suite, state: this.#state },
        {
          extraProposals: verifiedPackages.map((keyPackage) => ({
            add: { keyPackage },
            proposalType: 'add' as const,
          })),
          ratchetTreeExtension: true,
        },
      );
      const welcome = requireMlsWelcome(result.welcome);
      const commitFrame = MlsCommitFrame.create(encodeMessage(result.commit));
      const welcomeFrame = MlsWelcomeFrame.create(
        encodeMessage({
          version: 'mls10',
          welcome,
          wireformat: 'mls_welcome',
        }),
      );
      requirePrivateDeliveryCapacity('commit', commitFrame.toBytes());
      requirePrivateDeliveryCapacity('welcome', welcomeFrame.toBytes());

      return {
        consumed: result.consumed,
        value: {
          commit: commitFrame,
          session: new MlsGroupSession(result.newState, this.#verify),
          welcome: welcomeFrame,
        },
      };
    });
  }

  public async removeMembers(identities: Uint8Array[]): Promise<{
    readonly session: MlsGroupSession;
    readonly commit: MlsCommitFrame;
  }> {
    return this.transition(async () => {
      if (
        identities.length === 0 ||
        identities.length > MAX_GROUP_MEMBERS ||
        identities.some(
          (identity) =>
            !(identity instanceof Uint8Array) ||
            identity.length === 0 ||
            identity.length > MAX_IDENTITY_BYTES,
        )
      ) {
        throw new InvalidMlsStateError();
      }
      const targets = new Set(identities.map(identityKey));

      if (targets.size !== identities.length) throw new InvalidMlsStateError();
      const removed: number[] = [];
      this.#state.ratchetTree.forEach((node, nodeIndex) => {
        if (node?.nodeType !== 'leaf') return;
        const credential = node.leaf.credential;

        if (
          credential.credentialType === 'basic' &&
          targets.has(identityKey(credential.identity))
        ) {
          removed.push(nodeIndex / 2);
        }
      });

      if (removed.length !== targets.size) throw new InvalidMlsStateError();
      const suite = await getMlsCiphersuite();
      const result = await createCommit(
        { cipherSuite: suite, state: this.#state },
        {
          extraProposals: removed.map((leafIndex) => ({
            proposalType: 'remove' as const,
            remove: { removed: leafIndex },
          })),
          ratchetTreeExtension: true,
        },
      );
      const commitFrame = MlsCommitFrame.create(encodeMessage(result.commit));
      requirePrivateDeliveryCapacity('commit', commitFrame.toBytes());

      return {
        consumed: result.consumed,
        value: {
          commit: commitFrame,
          session: new MlsGroupSession(result.newState, this.#verify),
        },
      };
    });
  }

  public async refresh(): Promise<{
    readonly session: MlsGroupSession;
    readonly commit: MlsCommitFrame;
  }> {
    return this.transition(async () => {
      const suite = await getMlsCiphersuite();
      const result = await createCommit(
        { cipherSuite: suite, state: this.#state },
        { ratchetTreeExtension: true },
      );
      const commitFrame = MlsCommitFrame.create(encodeMessage(result.commit));
      requirePrivateDeliveryCapacity('commit', commitFrame.toBytes());

      return {
        consumed: result.consumed,
        value: {
          commit: commitFrame,
          session: new MlsGroupSession(result.newState, this.#verify),
        },
      };
    });
  }

  public async applyCommit(commit: MlsCommitFrame): Promise<MlsGroupSession> {
    return this.transition(async () => {
      const result = await this.process(commit.payloadBytes(), 'commit');

      if (result.kind !== 'newState') throw new InvalidMlsFrameError();

      return {
        consumed: result.consumed,
        value: new MlsGroupSession(result.newState, this.#verify),
      };
    });
  }

  public async encrypt(plaintext: Uint8Array): Promise<{
    readonly session: MlsGroupSession;
    readonly frame: MlsApplicationFrame;
  }> {
    return this.transition(async () => {
      if (
        !(plaintext instanceof Uint8Array) ||
        plaintext.length === 0 ||
        plaintext.length > MAX_MLS_APPLICATION_BYTES
      ) {
        throw new InvalidMlsFrameError();
      }
      const suite = await getMlsCiphersuite();
      const result = await createApplicationMessage(
        this.#state,
        new Uint8Array(plaintext),
        suite,
      );
      const applicationFrame = MlsApplicationFrame.create(
        encodeMessage({
          privateMessage: result.privateMessage,
          version: 'mls10',
          wireformat: 'mls_private_message',
        }),
      );
      requirePrivateDeliveryCapacity('application', applicationFrame.toBytes());

      return {
        consumed: result.consumed,
        value: {
          frame: applicationFrame,
          session: new MlsGroupSession(result.newState, this.#verify),
        },
      };
    });
  }

  public async decrypt(frame: MlsApplicationFrame): Promise<{
    readonly session: MlsGroupSession;
    readonly plaintext: Uint8Array;
  }> {
    return this.transition(async () => {
      const result = await this.process(frame.payloadBytes(), 'application');

      if (result.kind !== 'applicationMessage') {
        throw new InvalidMlsFrameError();
      }
      try {
        if (
          result.message.length === 0 ||
          result.message.length > MAX_MLS_APPLICATION_BYTES
        ) {
          throw new InvalidMlsFrameError();
        }

        return {
          consumed: result.consumed,
          value: {
            plaintext: new Uint8Array(result.message),
            session: new MlsGroupSession(result.newState, this.#verify),
          },
        };
      } finally {
        result.message.fill(0);
      }
    });
  }
}
