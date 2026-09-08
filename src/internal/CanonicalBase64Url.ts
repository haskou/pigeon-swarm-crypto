import { Buffer } from 'buffer';

import { InvalidPrivateOperationError } from '../errors/InvalidPrivateOperationError';

export class CanonicalBase64Url {
  public static encode(bytes: Uint8Array): string {
    return Buffer.from(bytes)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  public static decode(value: unknown, length: number): Uint8Array {
    if (
      typeof value !== 'string' ||
      value.length !== Math.ceil((length * 4) / 3)
    )
      throw new InvalidPrivateOperationError();
    const bytes = Buffer.from(
      value.replace(/-/g, '+').replace(/_/g, '/'),
      'base64',
    );

    if (bytes.length !== length || this.encode(bytes) !== value)
      throw new InvalidPrivateOperationError();

    return bytes;
  }
}
