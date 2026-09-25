import {
  ClientState,
  decodeGroupState,
  decodeMlsMessage,
  encodeGroupState,
  encodeMlsMessage,
  GroupState,
  KeyPackage,
  MLSMessage,
  PrivateKeyPackage,
} from 'ts-mls';
import { encodeGroupContext } from 'ts-mls/groupContext.js';

import { InvalidMlsFrameError } from '../InvalidMlsFrameError';
import { InvalidMlsStateError } from '../InvalidMlsStateError';

export const encodeMessage = (message: MLSMessage): Uint8Array =>
  encodeMlsMessage(message);

export const decodeMessage = (bytes: Uint8Array): MLSMessage => {
  try {
    const decoded = decodeMlsMessage(bytes, 0);

    if (decoded === undefined || decoded[1] !== bytes.length) {
      throw new InvalidMlsFrameError();
    }

    return decoded[0];
  } catch (error) {
    if (error instanceof InvalidMlsFrameError) throw error;
    throw new InvalidMlsFrameError();
  }
};

export const encodePublicKeyPackage = (keyPackage: KeyPackage): Uint8Array =>
  encodeMessage({
    keyPackage,
    version: 'mls10',
    wireformat: 'mls_key_package',
  });

export const decodePublicKeyPackage = (bytes: Uint8Array): KeyPackage => {
  const message = decodeMessage(bytes);

  if (message.wireformat !== 'mls_key_package') {
    throw new InvalidMlsFrameError();
  }

  return message.keyPackage;
};

export const encodeState = (state: GroupState): Uint8Array =>
  encodeGroupState(state);

export { encodeGroupContext };

export const decodeState = (
  bytes: Uint8Array,
): Omit<ClientState, 'clientConfig'> => {
  try {
    const decoded = decodeGroupState(bytes, 0);

    if (decoded === undefined || decoded[1] !== bytes.length) {
      throw new InvalidMlsStateError();
    }

    return decoded[0];
  } catch (error) {
    if (error instanceof InvalidMlsStateError) throw error;
    throw new InvalidMlsStateError();
  }
};

export const clonePrivateKeyPackage = (
  privatePackage: PrivateKeyPackage,
): PrivateKeyPackage => ({
  hpkePrivateKey: new Uint8Array(privatePackage.hpkePrivateKey),
  initPrivateKey: new Uint8Array(privatePackage.initPrivateKey),
  signaturePrivateKey: new Uint8Array(privatePackage.signaturePrivateKey),
});
