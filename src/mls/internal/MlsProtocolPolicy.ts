import { Credential, IncomingMessageCallback, Welcome } from 'ts-mls';

import { InvalidMlsStateError } from '../InvalidMlsStateError';
import { MlsCredentialVerifier } from '../MlsCredentialVerifier';

type IncomingMessage = Parameters<IncomingMessageCallback>[0];

export const validateMlsCredential = async (
  credential: Credential,
  signaturePublicKey: Uint8Array,
  verify: MlsCredentialVerifier,
): Promise<boolean> => {
  if (credential.credentialType !== 'basic') return false;

  return verify({
    identity: new Uint8Array(credential.identity),
    signaturePublicKey: new Uint8Array(signaturePublicKey),
  });
};

export const acceptsMlsMemberCount = (
  currentMemberCount: number,
  incoming: IncomingMessage,
  maximumMemberCount: number,
): boolean => {
  if (incoming.kind === 'proposal') return true;
  const additions = incoming.proposals.filter(
    ({ proposal }) => proposal.proposalType === 'add',
  ).length;
  const removals = incoming.proposals.filter(
    ({ proposal }) => proposal.proposalType === 'remove',
  ).length;
  const externalJoin = Number(incoming.senderLeafIndex === undefined);

  return (
    currentMemberCount + additions - removals + externalJoin <=
    maximumMemberCount
  );
};

export const requireMlsWelcome = (welcome: Welcome | undefined): Welcome => {
  if (welcome === undefined) throw new InvalidMlsStateError();

  return welcome;
};
