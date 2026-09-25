import { InvalidFormatError, StringValueObject } from '@haskou/value-objects';
import { Buffer } from 'buffer';

import { CryptoAdapter } from './internal/CryptoAdapter';
import { StrictBase64 } from './internal/StrictBase64';

export class UserRootKey {
  static readonly #LENGTH = 32;

  readonly #value: string | undefined;

  public readonly isNullObject: true | undefined;

  public static fromBase64(value: string | StringValueObject): UserRootKey {
    return new UserRootKey(value.valueOf());
  }

  public static generate(): UserRootKey {
    const bytes = CryptoAdapter.randomBytes(UserRootKey.#LENGTH);

    try {
      return new UserRootKey(bytes.toString('base64'));
    } finally {
      bytes.fill(0);
    }
  }

  public constructor(value: string | StringValueObject) {
    const serialized = value?.valueOf();

    if (serialized === undefined || serialized === null) {
      this.isNullObject = true;

      return;
    }
    const decoded = StrictBase64.decodeCanonicalFixedLength(
      serialized,
      new InvalidFormatError('[redacted key]'),
      UserRootKey.#LENGTH,
    );
    decoded.fill(0);
    this.#value = serialized;
  }

  public getBuffer(): Buffer {
    return Buffer.from(this.valueOf(), 'base64');
  }

  public isEqual(other: unknown): boolean {
    return other instanceof UserRootKey && other.#value === this.#value;
  }

  public toJSON(): never {
    throw new InvalidFormatError('[redacted key]');
  }

  public valueOf(): string {
    return this.#value as string;
  }
}
