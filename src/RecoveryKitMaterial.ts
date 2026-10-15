import { KeyPair } from './KeyPair';
import { UserRootKey } from './UserRootKey';

export type RecoveryKitMaterial = Readonly<{
  identityKeyPair: KeyPair;
  recoveryAuthorityKeyPair: KeyPair;
  rootKey: UserRootKey;
}>;
