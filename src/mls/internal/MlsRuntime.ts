import {
  CiphersuiteImpl,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
} from 'ts-mls';

import { CryptoAdapter } from '../../internal/CryptoAdapter';

let suite: Promise<CiphersuiteImpl> | undefined;

const withStrictEd25519 = async (
  pending: Promise<CiphersuiteImpl>,
): Promise<CiphersuiteImpl> => {
  const implementation = await pending;

  return {
    ...implementation,
    signature: {
      ...implementation.signature,
      verify: (publicKey, message, signature) =>
        Promise.resolve(
          publicKey.length === 32 &&
            signature.length === 64 &&
            CryptoAdapter.verify(signature, message, publicKey),
        ),
    },
  };
};

export const getMlsCiphersuite = (): Promise<CiphersuiteImpl> => {
  suite ??= withStrictEd25519(
    getCiphersuiteImpl(
      getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'),
    ),
  );

  return suite;
};
