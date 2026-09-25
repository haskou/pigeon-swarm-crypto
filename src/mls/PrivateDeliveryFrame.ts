import { Buffer } from 'buffer';
import canonicalize from 'canonicalize';

import { InvalidPrivateDeliveryError } from './InvalidPrivateDeliveryError';
import { PrivateDeliveryFrameKind } from './PrivateDeliveryFrameKind';

const KINDS = new Set<PrivateDeliveryFrameKind>([
  'mls-application',
  'mls-commit',
  'mls-welcome',
]);
const MAX_MLS_MESSAGE_BYTES = 1024 * 1024;

export class PrivateDeliveryFrame {
  private static create(
    kind: PrivateDeliveryFrameKind,
    mlsMessage: Uint8Array,
  ): PrivateDeliveryFrame {
    if (!(mlsMessage instanceof Uint8Array) || mlsMessage.length === 0) {
      throw new InvalidPrivateDeliveryError();
    }

    if (mlsMessage.length > MAX_MLS_MESSAGE_BYTES) {
      throw new InvalidPrivateDeliveryError();
    }

    return new PrivateDeliveryFrame(kind, new Uint8Array(mlsMessage));
  }

  private static parseJson(json: string): Record<string, unknown> {
    if (typeof json !== 'string' || Buffer.byteLength(json) > 1400000) {
      throw new InvalidPrivateDeliveryError();
    }
    const value = JSON.parse(json) as Record<string, unknown>;

    if (!value || Array.isArray(value) || Object.keys(value).length !== 3) {
      throw new InvalidPrivateDeliveryError();
    }

    if (canonicalize(value) !== json) throw new InvalidPrivateDeliveryError();

    return value;
  }

  private static parseMessage(value: Record<string, unknown>): Uint8Array {
    if (typeof value.mlsMessage !== 'string') {
      throw new InvalidPrivateDeliveryError();
    }
    const decoded = Buffer.from(value.mlsMessage, 'base64');

    if (decoded.length === 0 || decoded.length > MAX_MLS_MESSAGE_BYTES) {
      throw new InvalidPrivateDeliveryError();
    }

    if (decoded.toString('base64') !== value.mlsMessage) {
      throw new InvalidPrivateDeliveryError();
    }

    return decoded;
  }

  public static application(mlsMessage: Uint8Array): PrivateDeliveryFrame {
    return this.create('mls-application', mlsMessage);
  }

  public static commit(mlsMessage: Uint8Array): PrivateDeliveryFrame {
    return this.create('mls-commit', mlsMessage);
  }

  public static welcome(mlsMessage: Uint8Array): PrivateDeliveryFrame {
    return this.create('mls-welcome', mlsMessage);
  }

  public static fromCanonicalJson(json: string): PrivateDeliveryFrame {
    try {
      const value = this.parseJson(json);

      if (
        value.version !== 1 ||
        typeof value.kind !== 'string' ||
        !KINDS.has(value.kind as PrivateDeliveryFrameKind)
      ) {
        throw new InvalidPrivateDeliveryError();
      }

      return new PrivateDeliveryFrame(
        value.kind as PrivateDeliveryFrameKind,
        this.parseMessage(value),
      );
    } catch {
      throw new InvalidPrivateDeliveryError();
    }
  }

  private constructor(
    public readonly kind: PrivateDeliveryFrameKind,
    private readonly message: Uint8Array,
  ) {}

  public get mlsMessage(): Uint8Array {
    return new Uint8Array(this.message);
  }

  public toCanonicalJson(): string {
    return canonicalize({
      kind: this.kind,
      mlsMessage: Buffer.from(this.message).toString('base64'),
      version: 1,
    })!;
  }
}
