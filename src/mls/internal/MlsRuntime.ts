import {
  CiphersuiteImpl,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
} from 'ts-mls';

let suite: Promise<CiphersuiteImpl> | undefined;

export const getMlsCiphersuite = (): Promise<CiphersuiteImpl> => {
  suite ??= getCiphersuiteImpl(
    getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'),
  );

  return suite;
};
