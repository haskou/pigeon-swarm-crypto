import { Buffer } from 'buffer';

import { PrivateKey } from '../PrivateKey';
import { PublicKey } from '../PublicKey';
import { Signature } from '../Signature';

export class PreimageFields {
  public static readonly SHA256_HEX = /^[0-9a-f]{64}$/;
  public static readonly DIGEST = /^[A-Za-z0-9_-]{43}$/;

  private static isPlainObject(
    value: unknown,
  ): value is Record<string, unknown> {
    if (typeof value !== 'object' || value === null || Array.isArray(value))
      return false;
    const prototype = Object.getPrototypeOf(value);

    return prototype === Object.prototype || prototype === null;
  }

  public static guarded<T>(error: new () => Error, read: () => T): T {
    try {
      return read();
    } catch {
      throw new error();
    }
  }

  public static check(condition: boolean): asserts condition {
    if (!condition) throw new Error('Invalid preimage');
  }

  public static record(
    value: unknown,
    required: readonly string[],
    optional: readonly string[] = [],
  ): Record<string, unknown> {
    this.check(this.isPlainObject(value));
    const record = value as Record<string, unknown>;
    const present = Object.keys(record).filter(
      (key) => record[key] !== undefined,
    );
    this.check(
      present.every(
        (key) => required.includes(key) || optional.includes(key),
      ) && required.every((key) => record[key] !== undefined),
    );

    return record;
  }

  public static text(value: unknown, maxLength = Infinity): string {
    this.check(
      typeof value === 'string' &&
        value.length > 0 &&
        value.length <= maxLength,
    );

    return value as string;
  }

  public static counter(value: unknown): number {
    this.check(Number.isSafeInteger(value) && (value as number) >= 0);

    return value as number;
  }

  public static pattern(value: unknown, pattern: RegExp): string {
    this.check(typeof value === 'string' && pattern.test(value));

    return value as string;
  }

  public static literal<T>(value: unknown, expected: T): T {
    this.check(value === expected);

    return expected;
  }

  public static optional<T>(
    value: unknown,
    read: (present: unknown) => T,
  ): T | undefined {
    return value === undefined ? undefined : read(value);
  }

  public static list<T>(
    value: unknown,
    read: (item: unknown) => T,
    minLength = 0,
  ): T[] {
    this.check(Array.isArray(value) && value.length >= minLength);

    return Array.from(value as unknown[], read);
  }

  public static credential(value: unknown): string {
    return new PublicKey(this.text(value)).valueOf();
  }

  public static signature(value: unknown): string {
    return new Signature(this.text(value)).valueOf();
  }

  public static credentialBody(key: PublicKey): string {
    return key.valueOf().split('\n')[1];
  }

  /** Reads a credential given as its PEM body, the wire form of device keys. */
  public static bodyCredential(value: unknown): string {
    const body = this.text(value);
    new PublicKey(
      `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`,
    );

    return body;
  }

  public static signFor(
    content: string,
    key: PrivateKey,
    signer: string,
  ): Signature {
    this.check(this.credentialBody(key.getPublicKey()) === signer);

    return key.sign(content);
  }

  public static verify(
    content: string,
    signature: Signature,
    key: PublicKey,
  ): void {
    const encoded = signature.valueOf();
    this.check(
      Buffer.from(encoded, 'base64').toString('base64') === encoded &&
        key.isValidSignature(content, signature),
    );
  }

  public static verifyFor(
    content: string,
    signature: Signature,
    key: PublicKey,
    signer: string,
  ): void {
    this.check(this.credentialBody(key) === signer);
    this.verify(content, signature, key);
  }
}
