import { Buffer } from 'buffer';

import { InvalidPrivateOperationError } from '../errors/InvalidPrivateOperationError';
import { SymmetricKey } from '../SymmetricKey';

export class KeyMaterial {
  private static readonly KEY_LENGTH = 32;

  public static of(key: SymmetricKey): Buffer {
    if (!(key instanceof SymmetricKey))
      throw new InvalidPrivateOperationError();

    return key.getBuffer();
  }

  public static ofBytes(bytes: unknown): Uint8Array {
    if (
      !(bytes instanceof Uint8Array) ||
      bytes.length !== KeyMaterial.KEY_LENGTH
    )
      throw new InvalidPrivateOperationError();

    return bytes;
  }
}
