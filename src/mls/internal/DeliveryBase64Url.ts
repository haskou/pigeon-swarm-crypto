import { Buffer } from 'buffer';

import { InvalidPrivateDeliveryError } from '../InvalidPrivateDeliveryError';

export class DeliveryBase64Url {
  public static encode(value: Uint8Array): string {
    return Buffer.from(value)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/u, '');
  }

  public static decode(value: unknown, length: number): Uint8Array {
    if (
      typeof value !== 'string' ||
      value.length !== Math.ceil((length * 4) / 3)
    ) {
      throw new InvalidPrivateDeliveryError();
    }
    const bytes = Buffer.from(
      value.replace(/-/g, '+').replace(/_/g, '/'),
      'base64',
    );

    if (bytes.length !== length || this.encode(bytes) !== value) {
      throw new InvalidPrivateDeliveryError();
    }

    return bytes;
  }

  public static decodeAtMost(
    value: unknown,
    maximumLength: number,
  ): Uint8Array {
    if (
      typeof value !== 'string' ||
      value.length < 2 ||
      value.length > Math.ceil((maximumLength * 4) / 3)
    ) {
      throw new InvalidPrivateDeliveryError();
    }
    const bytes = Buffer.from(
      value.replace(/-/g, '+').replace(/_/g, '/'),
      'base64',
    );

    if (
      bytes.length === 0 ||
      bytes.length > maximumLength ||
      this.encode(bytes) !== value
    ) {
      throw new InvalidPrivateDeliveryError();
    }

    return bytes;
  }
}
