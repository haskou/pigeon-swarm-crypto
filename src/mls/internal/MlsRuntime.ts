import { ed25519 } from '@noble/curves/ed25519.js';
import {
  CiphersuiteImpl,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
} from 'ts-mls';

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
          ed25519.verify(signature, message, publicKey, { zip215: false }),
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
