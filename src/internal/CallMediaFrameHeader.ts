import { equalBytes } from '@noble/ciphers/utils.js';
import { Buffer } from 'buffer';

import { InvalidCallMediaFrameError } from '../errors/InvalidCallMediaFrameError';
import { BoundedText } from './BoundedText';
import { PreimageFields } from './PreimageFields';

export class CallMediaFrameHeader {
  static readonly #MARKER = Uint8Array.of(0x50, 0x53, 0x43, 0x45, 0x32);
  static readonly #MAX_EPOCH = 4294967295;
  static readonly #MAX_TRACK_BYTES = 64;
  static readonly #EPOCH_OFFSET = CallMediaFrameHeader.#MARKER.length;
  static readonly #SEALER_ID_OFFSET = CallMediaFrameHeader.#EPOCH_OFFSET + 4;
  static readonly #SEQUENCE_OFFSET = CallMediaFrameHeader.#SEALER_ID_OFFSET + 8;
  public static readonly LENGTH = CallMediaFrameHeader.#SEQUENCE_OFFSET + 8;
  public static readonly SEALER_ID_LENGTH = 8;

  public readonly epoch: number;
  public readonly sealerId: Uint8Array;
  public readonly sequence: number;

  public static epochOf(value: unknown): number {
    if (
      !Number.isInteger(value) ||
      (value as number) < 0 ||
      (value as number) > CallMediaFrameHeader.#MAX_EPOCH
    )
      throw new InvalidCallMediaFrameError();

    return value as number;
  }

  public static read(frame: unknown): CallMediaFrameHeader {
    if (
      !(frame instanceof Uint8Array) ||
      frame.length < CallMediaFrameHeader.LENGTH ||
      !equalBytes(
        frame.subarray(0, CallMediaFrameHeader.#MARKER.length),
        CallMediaFrameHeader.#MARKER,
      )
    )
      throw new InvalidCallMediaFrameError();
    const view = new DataView(
      frame.buffer,
      frame.byteOffset,
      CallMediaFrameHeader.LENGTH,
    );
    const sequence = view.getBigUint64(CallMediaFrameHeader.#SEQUENCE_OFFSET);

    if (sequence > BigInt(Number.MAX_SAFE_INTEGER))
      throw new InvalidCallMediaFrameError();

    return new CallMediaFrameHeader(
      view.getUint32(CallMediaFrameHeader.#EPOCH_OFFSET),
      frame.slice(
        CallMediaFrameHeader.#SEALER_ID_OFFSET,
        CallMediaFrameHeader.#SEQUENCE_OFFSET,
      ),
      Number(sequence),
    );
  }

  public constructor(epoch: number, sealerId: Uint8Array, sequence: number) {
    if (
      !(sealerId instanceof Uint8Array) ||
      sealerId.length !== CallMediaFrameHeader.SEALER_ID_LENGTH ||
      !Number.isSafeInteger(sequence) ||
      sequence < 0
    )
      throw new InvalidCallMediaFrameError();
    this.epoch = CallMediaFrameHeader.epochOf(epoch);
    this.sealerId = sealerId;
    this.sequence = sequence;
  }

  public additionalData(track: unknown): Uint8Array<ArrayBuffer> {
    return new Uint8Array(
      Buffer.concat([
        this.bytes(),
        PreimageFields.guarded(InvalidCallMediaFrameError, () =>
          BoundedText.encode(track, CallMediaFrameHeader.#MAX_TRACK_BYTES),
        ),
      ]),
    );
  }

  public bytes(): Uint8Array<ArrayBuffer> {
    const header = new Uint8Array(CallMediaFrameHeader.LENGTH);
    const view = new DataView(header.buffer);

    header.set(CallMediaFrameHeader.#MARKER);
    view.setUint32(CallMediaFrameHeader.#EPOCH_OFFSET, this.epoch);
    header.set(this.sealerId, CallMediaFrameHeader.#SEALER_ID_OFFSET);
    view.setBigUint64(
      CallMediaFrameHeader.#SEQUENCE_OFFSET,
      BigInt(this.sequence),
    );

    return header;
  }
}
