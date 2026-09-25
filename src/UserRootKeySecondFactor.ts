import {
  InvalidFormatError,
  NullObject,
  StringValueObject,
  ValueObject,
} from '@haskou/value-objects';
import { Buffer } from 'buffer';

import { CryptoAdapter } from './internal/CryptoAdapter';
import { StrictBase64 } from './internal/StrictBase64';

export class UserRootKeySecondFactor extends ValueObject<string> {
  private static readonly LENGTH = 32;

  public static fromBase64(
    value: string | StringValueObject,
  ): UserRootKeySecondFactor {
    return new UserRootKeySecondFactor(value.valueOf());
  }

  public static fromBuffer(value: Uint8Array): UserRootKeySecondFactor {
    const bytes = Buffer.from(value);

    try {
      return new UserRootKeySecondFactor(bytes.toString('base64'));
    } finally {
      bytes.fill(0);
    }
  }

  public static generate(): UserRootKeySecondFactor {
    const bytes = CryptoAdapter.randomBytes(UserRootKeySecondFactor.LENGTH);

    try {
      return new UserRootKeySecondFactor(bytes.toString('base64'));
    } finally {
      bytes.fill(0);
    }
  }

  constructor(value: string | StringValueObject) {
    super(value?.valueOf());

    if (NullObject.isNullObject(this)) return this;

    const decoded = StrictBase64.decodeCanonicalFixedLength(
      value.valueOf(),
      new InvalidFormatError('[redacted second factor]'),
      UserRootKeySecondFactor.LENGTH,
    );
    decoded.fill(0);
  }

  public getBuffer(): Buffer {
    return Buffer.from(this.valueOf(), 'base64');
  }
}
