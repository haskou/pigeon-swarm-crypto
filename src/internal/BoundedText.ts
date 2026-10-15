import { Buffer } from 'buffer';

import { InvalidPrivateOperationError } from '../errors/InvalidPrivateOperationError';

export class BoundedText {
  private static readonly LONE_SURROGATE = /[\uD800-\uDFFF]/u;

  public static encode(value: unknown, maxBytes: number): Buffer {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      value.length > maxBytes ||
      BoundedText.LONE_SURROGATE.test(value)
    )
      throw new InvalidPrivateOperationError();
    const bytes = Buffer.from(value, 'utf8');

    if (bytes.length > maxBytes) throw new InvalidPrivateOperationError();

    return bytes;
  }
}
