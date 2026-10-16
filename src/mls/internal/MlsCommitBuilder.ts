import type {
  CiphersuiteImpl,
  ClientState,
  Extension,
  MLSMessage,
  Proposal,
  Welcome,
} from 'ts-mls';

import {
  addHistoricalReceiverData,
  applyProposals,
  checkCanSendHandshakeMessages,
  makePskIndex,
  nextEpochContext,
} from 'ts-mls/clientState.js';
import { createGroupInfoWithRatchetTree } from 'ts-mls/createCommit.js';
import {
  createConfirmationTag,
  createContentCommitSignature,
} from 'ts-mls/framedContent.js';
import { makeKeyPackageRef } from 'ts-mls/keyPackage.js';
import { initializeEpoch } from 'ts-mls/keySchedule.js';
import { protect } from 'ts-mls/messageProtection.js';
import { getCommitSecret, pathToPathSecrets } from 'ts-mls/pathSecrets.js';
import {
  mergePrivateKeyPaths,
  toPrivateKeyPath,
  updateLeafKey,
} from 'ts-mls/privateKeyPath.js';
import { createSecretTree } from 'ts-mls/secretTree.js';
import { treeHashRoot } from 'ts-mls/treeHash.js';
import {
  leafToNodeIndex,
  leafWidth,
  toLeafIndex,
  toNodeIndex,
} from 'ts-mls/treemath.js';
import { createUpdatePath, firstCommonAncestor } from 'ts-mls/updatePath.js';
import { zeroOutUint8Array } from 'ts-mls/util/byteArray.js';
import { encryptGroupInfo, encryptGroupSecrets } from 'ts-mls/welcome.js';

import { InvalidMlsGroupError } from '../InvalidMlsGroupError';

export interface MlsCommitBuild {
  readonly newState: ClientState;
  readonly commit: MLSMessage;
  readonly welcome: Welcome | undefined;
}

/**
 * A member's commit as ts-mls 1.6.4 `createCommit` builds it with a private
 * wire format and the ratchet-tree GroupInfo extension, except that the
 * UpdatePath is encrypted to the provisional GroupContext carrying the
 * extensions a GroupContextExtensions proposal sets (RFC 9420 §12.4.2), as
 * every receiver decrypts it. ts-mls 1.6.4 encrypts it to the old
 * extensions, so no other member can process such a commit. It commits only
 * the proposals it is given, by value, never stored ones by reference, so
 * the policy has judged every change it carries; ts-mls refuses one that
 * removes its own committer. External commits and ReInit are refused. `cs`
 * is `getMlsCiphersuite()`, so it signs and verifies only with the strict
 * Ed25519 wrapper. Delete this builder once a stable ts-mls release carries
 * the fix.
 */
export const buildMlsCommit = async (
  state: ClientState,
  proposals: readonly Proposal[],
  authenticatedData: Uint8Array,
  groupInfoExtensions: readonly Extension[],
  cs: CiphersuiteImpl,
): Promise<MlsCommitBuild> => {
  checkCanSendHandshakeMessages(state);
  const wireformat = 'mls_private_message';
  const committer = toLeafIndex(state.privatePath.leafIndex);
  const allProposals = proposals.map((proposal) => ({
    proposal,
    proposalOrRefType: 'proposal' as const,
  }));
  const res = await applyProposals(
    state,
    allProposals,
    committer,
    makePskIndex(state, {}),
    true,
    cs,
  );
  const result = res.additionalResult;

  if (result.kind !== 'memberCommit') throw new InvalidMlsGroupError();
  // New members get their path secret from the welcome, not the path.
  const excludeNodes = result.addedLeafNodes.map(([leafIndex]) =>
    leafToNodeIndex(leafIndex),
  );
  const groupContextWithExtensions = {
    ...state.groupContext,
    extensions:
      result.extensions.length > 0
        ? result.extensions
        : state.groupContext.extensions,
  };
  // The fix: the path is encrypted to the context with the new extensions.
  const [tree, updatePath, pathSecrets, newPrivateKey] = res.needsUpdatePath
    ? await createUpdatePath(
        res.tree,
        committer,
        groupContextWithExtensions,
        state.signaturePrivateKey,
        cs,
        excludeNodes,
      )
    : [res.tree, undefined, [], undefined];
  const privatePath = mergePrivateKeyPaths(
    newPrivateKey === undefined
      ? state.privatePath
      : updateLeafKey(
          state.privatePath,
          await cs.hpke.exportPrivateKey(newPrivateKey),
        ),
    await toPrivateKeyPath(
      pathToPathSecrets(pathSecrets),
      state.privatePath.leafIndex,
      cs,
    ),
  );
  const lastPathSecret = pathSecrets.at(-1);
  const commitSecret =
    lastPathSecret === undefined
      ? new Uint8Array(cs.kdf.size)
      : await getCommitSecret(
          tree,
          toNodeIndex(lastPathSecret.nodeIndex),
          lastPathSecret.secret,
          cs.kdf,
        );
  const { framedContent, signature } = await createContentCommitSignature(
    state.groupContext,
    wireformat,
    { path: updatePath, proposals: allProposals },
    { leafIndex: state.privatePath.leafIndex, senderType: 'member' },
    authenticatedData,
    state.signaturePrivateKey,
    cs.signature,
  );
  const groupContext = await nextEpochContext(
    groupContextWithExtensions,
    wireformat,
    framedContent,
    signature,
    await treeHashRoot(tree, cs.hash),
    state.confirmationTag,
    cs.hash,
  );
  const epochSecrets = await initializeEpoch(
    state.keySchedule.initSecret,
    commitSecret,
    groupContext,
    res.pskSecret,
    cs.kdf,
  );
  const confirmationTag = await createConfirmationTag(
    epochSecrets.keySchedule.confirmationKey,
    groupContext.confirmedTranscriptHash,
    cs.hash,
  );
  const { privateMessage } = await protect(
    state.keySchedule.senderDataSecret,
    authenticatedData,
    state.groupContext,
    state.secretTree,
    {
      ...framedContent,
      auth: {
        confirmationTag,
        contentType: framedContent.contentType,
        signature,
      },
    },
    state.privatePath.leafIndex,
    state.clientConfig.paddingConfig,
    cs,
  );
  const encryptedGroupInfo = await encryptGroupInfo(
    await createGroupInfoWithRatchetTree(
      groupContext,
      confirmationTag,
      state,
      tree,
      [...groupInfoExtensions],
      cs,
    ),
    epochSecrets.welcomeSecret,
    cs,
  );
  const secrets = await Promise.all(
    result.addedLeafNodes.map(async ([leafIndex, keyPackage]) => {
      const nodeIndex = firstCommonAncestor(tree, leafIndex, committer);
      const pathSecret = pathSecrets.find(
        (secret) => secret.nodeIndex === nodeIndex,
      );
      const { ct, enc } = await encryptGroupSecrets(
        await cs.hpke.importPublicKey(keyPackage.initKey),
        encryptedGroupInfo,
        {
          joinerSecret: epochSecrets.joinerSecret,
          pathSecret: pathSecret?.secret,
          psks: res.pskIds,
        },
        cs.hpke,
      );

      return {
        encryptedGroupSecrets: { ciphertext: ct, kemOutput: enc },
        newMember: await makeKeyPackageRef(keyPackage, cs.hash),
      };
    }),
  );
  const [historicalReceiverData] = addHistoricalReceiverData(state);
  const newState: ClientState = {
    clientConfig: state.clientConfig,
    confirmationTag,
    groupActiveState: { kind: 'active' },
    groupContext,
    historicalReceiverData,
    keySchedule: epochSecrets.keySchedule,
    privatePath,
    ratchetTree: tree,
    secretTree: await createSecretTree(
      leafWidth(tree.length),
      epochSecrets.encryptionSecret,
      cs.kdf,
    ),
    signaturePrivateKey: state.signaturePrivateKey,
    unappliedProposals: {},
  };

  zeroOutUint8Array(commitSecret);
  zeroOutUint8Array(epochSecrets.encryptionSecret);
  zeroOutUint8Array(epochSecrets.joinerSecret);

  return {
    commit: { privateMessage, version: 'mls10', wireformat },
    newState,
    welcome:
      secrets.length > 0
        ? { cipherSuite: groupContext.cipherSuite, encryptedGroupInfo, secrets }
        : undefined,
  };
};
