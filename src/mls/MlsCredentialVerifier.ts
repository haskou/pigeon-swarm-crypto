import { MlsCredential } from './MlsCredential';

export type MlsCredentialVerifier = (
  credential: MlsCredential,
) => boolean | Promise<boolean>;
