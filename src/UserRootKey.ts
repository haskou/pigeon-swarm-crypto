import {
  InvalidFormatError,
  NullObject,
  StringValueObject,
  ValueObject,
} from '@haskou/value-objects';
import { Buffer } from 'buffer';

import { CryptoAdapter } from './internal/CryptoAdapter';
import { StrictBase64 } from './internal/StrictBase64';

export class UserRootKey extends ValueObject<string> {
  private static readonly LENGTH = 32;

  public static fromBase64(value: string | StringValueObject): UserRootKey {
    return new UserRootKey(value.valueOf());
  }

  public static generate(): UserRootKey {
    const bytes = CryptoAdapter.randomBytes(UserRootKey.LENGTH);

    try {
      return new UserRootKey(bytes.toString('base64'));
    } finally {
      bytes.fill(0);
    }
  }

  constructor(value: string | StringValueObject) {
    super(value?.valueOf());

    if (NullObject.isNullObject(this)) return this;

    const decoded = StrictBase64.decodeCanonicalFixedLength(
      value.valueOf(),
      new InvalidFormatError('[redacted key]'),
      UserRootKey.LENGTH,
    );
    decoded.fill(0);
  }

  public getBuffer(): Buffer {
    return Buffer.from(this.valueOf(), 'base64');
  }
}
