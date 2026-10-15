import canonicalize from 'canonicalize';

import { InvalidCanonicalJsonError } from './errors/InvalidCanonicalJsonError';

export class CanonicalJson {
  private static readonly LONE_SURROGATE = /[\uD800-\uDFFF]/u;
  public static readonly MAX_DEPTH = 64;

  private static fail(): never {
    throw new InvalidCanonicalJsonError();
  }

  private static text(value: string): string {
    if (this.LONE_SURROGATE.test(value)) this.fail();

    return value;
  }

  private static object(value: object, depth: number): unknown {
    if (Array.isArray(value))
      return Array.from(value, (item) =>
        item === undefined ? this.fail() : this.normalize(item, depth + 1),
      );
    const prototype = Object.getPrototypeOf(value);

    if (prototype !== Object.prototype && prototype !== null) this.fail();

    return Object.fromEntries(
      Object.entries(value)
        .filter(([, member]) => member !== undefined)
        .map(([key, member]) => [
          this.text(key),
          this.normalize(member, depth + 1),
        ]),
    );
  }

  private static normalize(value: unknown, depth: number): unknown {
    if (value === null || typeof value === 'boolean') return value;

    if (typeof value === 'string') return this.text(value);

    if (typeof value === 'number')
      return Number.isSafeInteger(value) ? value : this.fail();

    if (depth >= this.MAX_DEPTH || typeof value !== 'object') this.fail();

    return this.object(value, depth);
  }

  public static serialize(value: unknown): string {
    return canonicalize(this.normalize(value, 0))!;
  }
}
