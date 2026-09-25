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
import { getMlsCiphersuite } from './internal/MlsRuntime';
import { InvalidMlsFrameError } from './InvalidMlsFrameError';
import { InvalidMlsStateError } from './InvalidMlsStateError';
import { MlsApplicationFrame } from './MlsApplicationFrame';
import { MlsCommitFrame } from './MlsCommitFrame';
import { MlsCredentialVerifier } from './MlsCredentialVerifier';
import { MlsJoinPackage } from './MlsJoinPackage';
import { MlsWelcomeFrame } from './MlsWelcomeFrame';
import { ProtectedMlsGroupState } from './ProtectedMlsGroupState';

const createConfig = (verify: MlsCredentialVerifier): ClientConfig => ({
  authService: {
    async validateCredential(credential, signaturePublicKey) {
      if (credential.credentialType !== 'basic') return false;

      return verify({
        identity: new Uint8Array(credential.identity),
        signaturePublicKey: new Uint8Array(signaturePublicKey),
      });
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
const MAX_APPLICATION_BYTES = 1024 * 1024 - 4096;

const eraseConsumed = (consumed: Uint8Array[]): void => {
  consumed.forEach(zeroOutUint8Array);
};

const identityKey = (identity: Uint8Array): string => {
  let key = '';
  for (const byte of identity) key += String.fromCharCode(byte);

  return key;
};

export class MlsGroupSession {
  readonly #state: ClientState;

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
          credential.credentialType !== 'basic' ||
          !(await verify({
            identity: new Uint8Array(credential.identity),
            signaturePublicKey: new Uint8Array(
              keyPackage.leafNode.signaturePublicKey,
            ),
          }))
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

    if (!(await verify(founder.credential()))) {
      throw new InvalidMlsStateError();
    }
    const suite = await getMlsCiphersuite();
    const state = await createGroup(
      new Uint8Array(groupId),
      founder.copyPublicPackage(),
      founder.consumePrivatePackage(),
      [],
      suite,
      createConfig(verify),
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
      const state = await joinGroup(
        message.welcome,
        joinPackage.copyPublicPackage(),
        joinPackage.consumePrivatePackage(),
        emptyPskIndex,
        suite,
        undefined,
        undefined,
        createConfig(verify),
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
  ): MlsGroupSession {
    const bytes = protectedState.unlock(rootKey);

    try {
      const decoded = decodeState(bytes);
      const owned = decodeState(encodeState(decoded));

      if (owned.groupContext.epoch !== expectedEpoch) {
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
    this.#state = state;
    this.#verify = verify;
  }

  private async process(bytes: Uint8Array) {
    try {
      const message = decodeMessage(bytes);

      if (
        message.wireformat !== 'mls_private_message' &&
        message.wireformat !== 'mls_public_message'
      ) {
        throw new InvalidMlsFrameError();
      }
      const suite = await getMlsCiphersuite();

      return await processMessage(
        message,
        this.#state,
        emptyPskIndex,
        () => 'accept',
        suite,
      );
    } catch {
      throw new InvalidMlsFrameError();
    }
  }

  public get epoch(): bigint {
    return this.#state.groupContext.epoch;
  }

  public get active(): boolean {
    return this.#state.groupActiveState.kind === 'active';
  }

  public get contextHash(): string {
    return DeliveryBase64Url.encode(
      sha256(encodeGroupContext(this.#state.groupContext)),
    );
  }

  public protectState(rootKey: UserRootKey): ProtectedMlsGroupState {
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
    const memberCount = this.#state.ratchetTree.filter(
      (node) => node?.nodeType === 'leaf',
    ).length;

    if (
      publicPackages.length === 0 ||
      publicPackages.length > MAX_GROUP_MEMBERS - memberCount
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
    try {
      if (result.welcome === undefined) throw new InvalidMlsStateError();

      return {
        commit: MlsCommitFrame.create(encodeMessage(result.commit)),
        session: new MlsGroupSession(result.newState, this.#verify),
        welcome: MlsWelcomeFrame.create(
          encodeMessage({
            version: 'mls10',
            welcome: result.welcome,
            wireformat: 'mls_welcome',
          }),
        ),
      };
    } finally {
      eraseConsumed(result.consumed);
    }
  }

  public async removeMembers(identities: Uint8Array[]): Promise<{
    readonly session: MlsGroupSession;
    readonly commit: MlsCommitFrame;
  }> {
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
    try {
      return {
        commit: MlsCommitFrame.create(encodeMessage(result.commit)),
        session: new MlsGroupSession(result.newState, this.#verify),
      };
    } finally {
      eraseConsumed(result.consumed);
    }
  }

  public async refresh(): Promise<{
    readonly session: MlsGroupSession;
    readonly commit: MlsCommitFrame;
  }> {
    const suite = await getMlsCiphersuite();
    const result = await createCommit(
      { cipherSuite: suite, state: this.#state },
      { ratchetTreeExtension: true },
    );
    try {
      return {
        commit: MlsCommitFrame.create(encodeMessage(result.commit)),
        session: new MlsGroupSession(result.newState, this.#verify),
      };
    } finally {
      eraseConsumed(result.consumed);
    }
  }

  public async applyCommit(commit: MlsCommitFrame): Promise<MlsGroupSession> {
    const result = await this.process(commit.payloadBytes());
    try {
      if (result.kind !== 'newState') throw new InvalidMlsFrameError();

      return new MlsGroupSession(result.newState, this.#verify);
    } finally {
      eraseConsumed(result.consumed);
    }
  }

  public async encrypt(plaintext: Uint8Array): Promise<{
    readonly session: MlsGroupSession;
    readonly frame: MlsApplicationFrame;
  }> {
    if (
      !(plaintext instanceof Uint8Array) ||
      plaintext.length === 0 ||
      plaintext.length > MAX_APPLICATION_BYTES
    ) {
      throw new InvalidMlsFrameError();
    }
    const suite = await getMlsCiphersuite();
    const result = await createApplicationMessage(
      this.#state,
      new Uint8Array(plaintext),
      suite,
    );
    try {
      return {
        frame: MlsApplicationFrame.create(
          encodeMessage({
            privateMessage: result.privateMessage,
            version: 'mls10',
            wireformat: 'mls_private_message',
          }),
        ),
        session: new MlsGroupSession(result.newState, this.#verify),
      };
    } finally {
      eraseConsumed(result.consumed);
    }
  }

  public async decrypt(frame: MlsApplicationFrame): Promise<{
    readonly session: MlsGroupSession;
    readonly plaintext: Uint8Array;
  }> {
    const result = await this.process(frame.payloadBytes());
    try {
      if (result.kind !== 'applicationMessage') {
        throw new InvalidMlsFrameError();
      }
      const plaintext = new Uint8Array(result.message);
      result.message.fill(0);

      return {
        plaintext,
        session: new MlsGroupSession(result.newState, this.#verify),
      };
    } finally {
      eraseConsumed(result.consumed);
    }
  }
}
