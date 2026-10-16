import { Buffer } from 'buffer';

import { InvalidCallMediaFrameError } from '../errors/InvalidCallMediaFrameError';
import { BoundedText } from './BoundedText';
import { PreimageFields } from './PreimageFields';

export class CallMediaFrameContext {
  static readonly #MAX_ID_BYTES = 256;

  readonly #callId: Buffer;
  readonly #senderId: Buffer;

  private static id(value: unknown): Buffer {
    return PreimageFields.guarded(InvalidCallMediaFrameError, () =>
      BoundedText.encode(value, CallMediaFrameContext.#MAX_ID_BYTES),
    );
  }

  private static lengthPrefixed(value: Buffer): Buffer {
    const length = Buffer.alloc(2);

    new DataView(length.buffer, length.byteOffset, 2).setUint16(
      0,
      value.length,
    );

    return Buffer.concat([length, value]);
  }

  public static of(callId: unknown, senderId: unknown): CallMediaFrameContext {
    return new CallMediaFrameContext(
      CallMediaFrameContext.id(callId),
      CallMediaFrameContext.id(senderId),
    );
  }

  private constructor(callId: Buffer, senderId: Buffer) {
    this.#callId = callId;
    this.#senderId = senderId;
  }

  public info(label: string, epoch: number, sealerId: Uint8Array): Buffer {
    const epochBytes = Buffer.alloc(4);

    new DataView(epochBytes.buffer, epochBytes.byteOffset, 4).setUint32(
      0,
      epoch,
    );

    return Buffer.concat([
      Buffer.from(label, 'utf8'),
      CallMediaFrameContext.lengthPrefixed(this.#callId),
      CallMediaFrameContext.lengthPrefixed(this.#senderId),
      epochBytes,
      sealerId,
    ]);
  }
}
