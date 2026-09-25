import { InvalidMlsStateError } from '../InvalidMlsStateError';

const MAGIC = Uint8Array.of(0x50, 0x53, 0x42, 0x01);

export class BinarySecretCodec {
  private static ensureHeader(
    encoded: Uint8Array,
    expectedParts: number,
    maxBytes: number,
  ): void {
    if (
      !(encoded instanceof Uint8Array) ||
      encoded.length > maxBytes ||
      encoded.length < MAGIC.length + 1 ||
      !MAGIC.every((value, index) => encoded[index] === value) ||
      encoded[MAGIC.length] !== expectedParts
    ) {
      throw new InvalidMlsStateError();
    }
  }

  private static readPart(
    encoded: Uint8Array,
    view: DataView,
    offset: number,
  ): readonly [Uint8Array, number] {
    if (offset + 4 > encoded.length) throw new InvalidMlsStateError();
    const length = view.getUint32(offset);
    const start = offset + 4;

    if (length === 0 || start + length > encoded.length) {
      throw new InvalidMlsStateError();
    }

    return [encoded.slice(start, start + length), start + length];
  }

  public static decode(
    encoded: Uint8Array,
    expectedParts: number,
    maxBytes: number,
  ): Uint8Array[] {
    this.ensureHeader(encoded, expectedParts, maxBytes);
    const view = new DataView(
      encoded.buffer,
      encoded.byteOffset,
      encoded.byteLength,
    );
    const parts: Uint8Array[] = [];
    let offset = MAGIC.length + 1;

    for (let index = 0; index < expectedParts; index += 1) {
      const [part, nextOffset] = this.readPart(encoded, view, offset);
      parts.push(part);
      offset = nextOffset;
    }

    if (offset !== encoded.length) throw new InvalidMlsStateError();

    return parts;
  }

  public static encode(parts: Uint8Array[], maxBytes: number): Uint8Array {
    if (parts.length === 0 || parts.length > 255) {
      throw new InvalidMlsStateError();
    }
    const length =
      MAGIC.length +
      1 +
      parts.reduce((total, part) => total + 4 + part.length, 0);

    if (
      length > maxBytes ||
      parts.some((part) => !(part instanceof Uint8Array) || part.length === 0)
    ) {
      throw new InvalidMlsStateError();
    }
    const encoded = new Uint8Array(length);
    const view = new DataView(encoded.buffer);
    encoded.set(MAGIC);
    encoded[MAGIC.length] = parts.length;
    let offset = MAGIC.length + 1;

    for (const part of parts) {
      view.setUint32(offset, part.length);
      offset += 4;
      encoded.set(part, offset);
      offset += part.length;
    }

    return encoded;
  }
}
