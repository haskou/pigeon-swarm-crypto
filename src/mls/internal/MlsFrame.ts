import { InvalidMlsFrameError } from '../InvalidMlsFrameError';

const MAGIC = Uint8Array.of(0x50, 0x53, 0x4d, 0x01);
const MAX_PAYLOAD_BYTES = 1024 * 1024;

export enum FrameKind {
  Application = 1,
  Commit = 2,
  Welcome = 3,
}

export abstract class MlsFrame {
  protected static parse(bytes: Uint8Array, kind: FrameKind): Uint8Array {
    if (
      !(bytes instanceof Uint8Array) ||
      bytes.length <= MAGIC.length + 1 ||
      bytes.length > MAX_PAYLOAD_BYTES + MAGIC.length + 1 ||
      bytes[MAGIC.length] !== kind ||
      !MAGIC.every((value, index) => bytes[index] === value)
    ) {
      throw new InvalidMlsFrameError();
    }

    return bytes.slice(MAGIC.length + 1);
  }

  protected static validatePayload(payload: Uint8Array): Uint8Array {
    if (
      !(payload instanceof Uint8Array) ||
      payload.length === 0 ||
      payload.length > MAX_PAYLOAD_BYTES
    ) {
      throw new InvalidMlsFrameError();
    }

    return new Uint8Array(payload);
  }

  protected constructor(
    private readonly kind: FrameKind,
    private readonly payload: Uint8Array,
  ) {}

  public toBytes(): Uint8Array {
    const frame = new Uint8Array(MAGIC.length + 1 + this.payload.length);
    frame.set(MAGIC);
    frame[MAGIC.length] = this.kind;
    frame.set(this.payload, MAGIC.length + 1);

    return frame;
  }

  public payloadBytes(): Uint8Array {
    return new Uint8Array(this.payload);
  }
}
