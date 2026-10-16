import type { IdentityProfile } from './IdentityProfile';

/** The identity document fields the identity key signs. */
export type IdentitySignaturePayload = Readonly<{
  admissionNonce?: string;
  authorizationRevision: number;
  deviceCredential: string;
  deviceCredentialCommitment: string;
  id: string;
  mailboxHome?: string;
  networks: readonly string[];
  previousIdentityExternalIdentifier?: string;
  profile: IdentityProfile;
  recoveryAuthority: string;
  timestamp: number;
  version: number;
}>;
