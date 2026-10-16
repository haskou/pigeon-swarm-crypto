import { InvalidFormatError, StringValueObject } from '@haskou/value-objects';
import { equalBytes } from '@noble/ciphers/utils.js';
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

  /** Compares the decoded keys in constant time, then wipes both copies. */
  public isEqual(other: unknown): boolean {
    if (!(other instanceof UserRootKey)) return false;

    if (this.isNullObject || other.isNullObject) {
      return this.isNullObject === other.isNullObject;
    }
    const mine = this.getBuffer();
    const theirs = other.getBuffer();

    try {
      return equalBytes(mine, theirs);
    } finally {
      mine.fill(0);
      theirs.fill(0);
    }
  }

  public toJSON(): never {
    throw new InvalidFormatError('[redacted key]');
  }

  public valueOf(): string {
    return this.#value as string;
  }
}
