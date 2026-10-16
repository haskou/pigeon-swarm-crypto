import { InvalidRecoveryKeyError } from './errors/InvalidRecoveryKeyError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CryptoAdapter } from './internal/CryptoAdapter';

export class RecoveryKey {
  static readonly #LENGTH = 32;
  static readonly #PREFIX = 'psrk1.';

  readonly #value: string;

  private static decode(value: unknown): Uint8Array {
    if (typeof value !== 'string' || !value.startsWith(RecoveryKey.#PREFIX))
      throw new InvalidRecoveryKeyError();

    return CanonicalBase64Url.decode(
      value.slice(RecoveryKey.#PREFIX.length),
      RecoveryKey.#LENGTH,
    );
  }

  public static fromString(value: string): RecoveryKey {
    try {
      RecoveryKey.decode(value).fill(0);

      return new RecoveryKey(value);
    } catch {
      throw new InvalidRecoveryKeyError();
    }
  }

  public static generate(): RecoveryKey {
    const bytes = CryptoAdapter.randomBytes(RecoveryKey.#LENGTH);

    try {
      return new RecoveryKey(
        `${RecoveryKey.#PREFIX}${CanonicalBase64Url.encode(bytes)}`,
      );
    } finally {
      bytes.fill(0);
    }
  }

  public static isValid(value: unknown): boolean {
    try {
      RecoveryKey.decode(value).fill(0);

      return true;
    } catch {
      return false;
    }
  }

  private constructor(value: string) {
    this.#value = value;
  }

  public getBytes(): Uint8Array {
    return RecoveryKey.decode(this.#value);
  }

  public isEqual(other: unknown): boolean {
    return other instanceof RecoveryKey && other.#value === this.#value;
  }

  public toJSON(): never {
    throw new InvalidRecoveryKeyError();
  }

  public valueOf(): string {
    return this.#value;
  }
}
