import type { DeviceAuthorizationOperation } from './DeviceAuthorizationOperation';
import type { DeviceCompromisedCredential } from './DeviceCompromisedCredential';

/** The transition fields both device authorization signatures commit to. */
export type DeviceAuthorizationTransitionPreimage = Readonly<{
  authorCredential?: string;
  authorizedAt?: number;
  compromisedCredentials?: readonly DeviceCompromisedCredential[];
  compromisedSince?: number;
  epoch: string;
  identityId: string;
  operation: DeviceAuthorizationOperation;
  operationId: string;
  pairingExpiration?: number;
  pairingId?: string;
  previousRevision: number;
  revision: number;
  targetCredential: string;
  targetCredentialCommitment: string;
}>;
