import {
  type AuthenticationService,
  type CiphersuiteImpl,
  type ClientConfig,
  type MLSMessage,
  type ClientState,
  type Credential,
  type Extension,
  type KeyPackage,
  type PrivateKeyPackage,
  type PrivateMessage,
  type Proposal,
  type RatchetTree,
  type Welcome,
  decodeMlsMessage,
  defaultKeyPackageEqualityConfig,
  defaultKeyRetentionConfig,
  defaultLifetimeConfig,
  defaultPaddingConfig,
  emptyPskIndex,
} from 'ts-mls';
import { extensionTypeToNumber } from 'ts-mls/extension.js';
import { makeKeyPackageRef } from 'ts-mls/keyPackage.js';
import {
  CodecError,
  CryptoError,
  CryptoVerificationError,
  InternalError,
  ValidationError,
} from 'ts-mls/mlsError.js';
import { accumulatePskSecret } from 'ts-mls/pskIndex.js';
import { decryptGroupInfo, decryptGroupSecrets } from 'ts-mls/welcome.js';

import type { MlsContextExtension } from '../MlsContextExtension';
import type { MlsLeafOwner } from '../MlsLeafOwner';
import type { MlsMembershipChange } from '../MlsMembershipChange';

import { InvalidMlsCredentialError } from '../InvalidMlsCredentialError';
import { InvalidMlsExtensionError } from '../InvalidMlsExtensionError';
import { InvalidMlsGroupError } from '../InvalidMlsGroupError';
import { MlsLeafCredential } from '../MlsLeafCredential';
import { MlsRosterFrontier } from '../MlsRosterFrontier';

/** The value, or a rejection when the protocol left it out. */
export const defined = <T>(value: T | undefined): T => {
  if (value === undefined) throw new InvalidMlsGroupError();

  return value;
};

/**
 * Turns what ts-mls or a codec throws on hostile input into the group's one
 * rejection; anything else, such as a membership policy failing or a misuse
 * of ts-mls, passes.
 */
export const rejection = (error: unknown): unknown =>
  [
    CodecError,
    CryptoError,
    CryptoVerificationError,
    InternalError,
    InvalidMlsCredentialError,
    InvalidMlsExtensionError,
    ValidationError,
  ].some((type) => error instanceof type)
    ? new InvalidMlsGroupError()
    : error;

/** The owner a leaf credential names, without verifying its signatures. */
export const ownerOf = (credential: Credential): MlsLeafOwner => {
  if (credential.credentialType !== 'basic')
    throw new InvalidMlsCredentialError();

  return MlsLeafCredential.ownerOf(credential.identity);
};

/** The owner, once the identity and device both signed the leaf's key. */
export const verifiedOwner = (
  credential: Credential,
  signaturePublicKey: Uint8Array,
): MlsLeafOwner => {
  if (credential.credentialType !== 'basic')
    throw new InvalidMlsCredentialError();

  return MlsLeafCredential.verify(credential.identity, signaturePublicKey);
};

/**
 * Every leaf credential must be signed by the identity and device it names;
 * ts-mls asks this of every key package, update path, welcome tree leaf and
 * welcome signer. Whether the identity may hold a leaf is the policy's call.
 */
const authService: AuthenticationService = {
  validateCredential: (credential, signaturePublicKey) => {
    try {
      verifiedOwner(credential, signaturePublicKey);

      return Promise.resolve(true);
    } catch {
      return Promise.resolve(false);
    }
  },
};

export const clientConfig: ClientConfig = {
  authService,
  keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
  keyRetentionConfig: { ...defaultKeyRetentionConfig, retainKeysForEpochs: 8 },
  lifetimeConfig: defaultLifetimeConfig,
  paddingConfig: defaultPaddingConfig,
};

/** One MLS message of the expected wire format, or a rejection. */
export const decodeMessage = <W extends MLSMessage['wireformat']>(
  bytes: Uint8Array,
  wireformat: W,
): Extract<MLSMessage, { wireformat: W }> => {
  let decoded: MLSMessage | undefined;

  try {
    decoded = decodeMlsMessage(bytes, 0)?.[0];
  } catch {
    throw new InvalidMlsGroupError();
  }

  if (decoded?.wireformat !== wireformat) throw new InvalidMlsGroupError();

  return decoded as Extract<MLSMessage, { wireformat: W }>;
};

/** The owner of a key package, only when its credential verifies. */
export const keyPackageOwner = ({ leafNode }: KeyPackage): MlsLeafOwner =>
  verifiedOwner(leafNode.credential, leafNode.signaturePublicKey);

/** The leaf at `leafIndex`, or a rejection for a blank or parent node. */
export const leafAt = (
  tree: RatchetTree,
  leafIndex: number,
): Extract<RatchetTree[number], { nodeType: 'leaf' }> => {
  const node = tree[leafIndex * 2];

  if (node?.nodeType !== 'leaf') throw new InvalidMlsGroupError();

  return node;
};

/** The owner of a leaf, only when its credential verifies. */
export const verifiedOwnerAt = (
  tree: RatchetTree,
  leafIndex: number,
): MlsLeafOwner => {
  const { leaf } = leafAt(tree, leafIndex);

  return verifiedOwner(leaf.credential, leaf.signaturePublicKey);
};

/** GroupContext extensions by number, as the membership policy reads them. */
export const contextOf = (
  extensions: readonly Extension[],
): MlsContextExtension[] =>
  extensions.map(({ extensionData, extensionType }) => ({
    extensionData,
    extensionType: extensionTypeToNumber(extensionType),
  }));

/**
 * What a commit's proposals do to membership, by identity, judged against
 * the tree and GroupContext they apply to. Only adds, removals, updates and
 * GroupContextExtensions proposals may be in it; ts-mls already refuses a
 * commit with more than one of the latter (RFC 9420 §12.2). Every owner it
 * names, the committer first, comes from a credential that verifies.
 */
export const membershipChange = (
  from: Pick<ClientState, 'groupContext' | 'ratchetTree'>,
  committerLeaf: number,
  proposals: readonly Proposal[],
): MlsMembershipChange => {
  const tree = from.ratchetTree;
  const committer = verifiedOwnerAt(tree, committerLeaf);
  const added: string[] = [];
  const removed: string[] = [];
  const proposedContexts: MlsContextExtension[][] = [];

  for (const proposal of proposals) {
    if (proposal.proposalType === 'add')
      added.push(keyPackageOwner(proposal.add.keyPackage).identityId);
    else if (proposal.proposalType === 'remove')
      removed.push(verifiedOwnerAt(tree, proposal.remove.removed).identityId);
    else if (proposal.proposalType === 'group_context_extensions')
      proposedContexts.push(
        contextOf(proposal.groupContextExtensions.extensions),
      );
    else if (proposal.proposalType !== 'update')
      throw new InvalidMlsGroupError();
  }

  const holders = tree.flatMap((node) =>
    node?.nodeType === 'leaf' ? [ownerOf(node.leaf.credential).identityId] : [],
  );

  return {
    added,
    committer: committer.identityId,
    committerDevice: committer.deviceCredential,
    context: contextOf(from.groupContext.extensions),
    holders,
    proposedContext: proposedContexts[0],
    removed,
  };
};

/**
 * Rejects a commit whose update path left the committer's leaf, validated
 * only after the judgement, to another identity or device than judged.
 */
export const assertCommitterKept = (
  tree: RatchetTree,
  committerLeaf: number,
  { committer, committerDevice }: MlsMembershipChange,
): void => {
  const owner = verifiedOwnerAt(tree, committerLeaf);

  if (
    owner.identityId !== committer ||
    owner.deviceCredential !== committerDevice
  )
    throw new InvalidMlsGroupError();
};

/** A published commit and the roster frontier its committer bound. */
export const readCommit = (
  bytes: Uint8Array,
): { frontier: readonly string[]; message: PrivateMessage } => {
  const { privateMessage } = decodeMessage(bytes, 'mls_private_message');

  return {
    frontier: MlsRosterFrontier.decode(privateMessage.authenticatedData),
    message: privateMessage,
  };
};

/**
 * The leaf that signed a welcome. The join verified the GroupInfo signature
 * but does not say whose it is; the same secrets open it again to name it.
 */
export const welcomeSigner = async (
  welcome: Welcome,
  keyPackage: KeyPackage,
  privatePackage: PrivateKeyPackage,
  tree: RatchetTree,
  cs: CiphersuiteImpl,
): Promise<MlsLeafOwner> => {
  const secrets = defined(
    await decryptGroupSecrets(
      await cs.hpke.importPrivateKey(privatePackage.initPrivateKey),
      await makeKeyPackageRef(keyPackage, cs.hash),
      welcome,
      cs.hpke,
    ),
  );
  const [pskSecret] = await accumulatePskSecret(
    secrets.psks,
    emptyPskIndex,
    cs,
    new Uint8Array(cs.kdf.size),
  );
  const info = defined(
    await decryptGroupInfo(welcome, secrets.joinerSecret, pskSecret, cs),
  );

  return ownerOf(leafAt(tree, Number(info.signer)).leaf.credential);
};

/**
 * The state this device left at the epoch `state` is in, when it stepped
 * back from that very epoch: the same epoch authenticator means the same
 * epoch secret. Left states up to that epoch are dropped from `left`.
 */
export const resume = (
  left: ClientState[],
  state: ClientState,
): ClientState => {
  const epoch = state.groupContext.epoch;
  const match = left.find(
    (stashed) =>
      stashed.groupContext.epoch === epoch &&
      stashed.keySchedule.epochAuthenticator.every(
        (byte, index) => state.keySchedule.epochAuthenticator[index] === byte,
      ),
  );

  left.splice(
    0,
    left.length,
    ...left.filter((stashed) => stashed.groupContext.epoch > epoch),
  );

  return match ?? state;
};
