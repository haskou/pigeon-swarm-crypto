import { NullObject } from '@haskou/value-objects';

import { InvalidPrivateNetworkKeyError } from '../errors/InvalidPrivateNetworkKeyError';
import { PrivateKey } from '../PrivateKey';
import { CryptoAdapter } from './CryptoAdapter';

export class PrivateNetworkSecret {
  public static derive(
    networkKey: PrivateKey,
    label: string,
    length: number,
  ): Uint8Array {
    if (
      !(networkKey instanceof PrivateKey) ||
      NullObject.isNullObject(networkKey)
    )
      throw new InvalidPrivateNetworkKeyError();

    return CryptoAdapter.hkdfSha256(
      CryptoAdapter.privateKeyToSeed(networkKey.valueOf()),
      label,
      length,
    );
  }
}
