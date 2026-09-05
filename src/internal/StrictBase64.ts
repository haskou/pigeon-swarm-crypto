import { assert } from '@haskou/value-objects';
import { Buffer } from 'buffer';

import { StrictBase64Options } from './StrictBase64Options';

export class StrictBase64 {
  private static readonly INVALID_CHARACTER = /[^A-Za-z0-9+/]/;

  private static hasValidCharacters(value: string): boolean {
    const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
    const content = value.slice(0, value.length - padding);

    return !StrictBase64.INVALID_CHARACTER.test(content);
  }

  public static getDecodedLength(value: string): number {
    const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;

    return (value.length / 4) * 3 - padding;
  }

  public static ensure(
    value: string,
    error: Error,
    options: StrictBase64Options = {},
  ): void {
    assert(
      (options.allowEmpty === true || value.length > 0) &&
        value.length % 4 === 0 &&
        StrictBase64.hasValidCharacters(value),
      error,
    );
  }

  public static ensureDecodedLength(
    value: string,
    error: Error,
    length: number,
    options: StrictBase64Options = {},
  ): void {
    assert(StrictBase64.getDecodedLength(value) === length, error);
    StrictBase64.ensure(value, error, options);
  }

  public static decode(
    value: string,
    error: Error,
    options: StrictBase64Options = {},
  ): Buffer {
    StrictBase64.ensure(value, error, options);

    return Buffer.from(value, 'base64');
  }

  public static decodeFixedLength(
    value: string,
    error: Error,
    length: number,
  ): Buffer {
    StrictBase64.ensureDecodedLength(value, error, length);

    return Buffer.from(value, 'base64');
  }

  public static decodeCanonicalFixedLength(
    value: string,
    error: Error,
    length: number,
  ): Buffer {
    const decoded = StrictBase64.decodeFixedLength(value, error, length);

    assert(decoded.toString('base64') === value, error);

    return decoded;
  }
}
