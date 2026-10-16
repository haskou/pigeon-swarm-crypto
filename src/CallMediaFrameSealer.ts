import { CallMediaFrameSealerContext } from './CallMediaFrameSealerContext';
import { InvalidCallMediaFrameError } from './errors/InvalidCallMediaFrameError';
import { CallMediaFrameContext } from './internal/CallMediaFrameContext';
import { CallMediaFrameHeader } from './internal/CallMediaFrameHeader';
import { CallMediaSealerKey } from './internal/CallMediaSealerKey';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { SymmetricKey } from './SymmetricKey';

export class CallMediaFrameSealer {
  readonly #epoch: number;
  readonly #key: CallMediaSealerKey;
  readonly #sealerId: Uint8Array;
  #sequence = 0;

  public static async create(
    callKey: SymmetricKey,
    context: CallMediaFrameSealerContext,
  ): Promise<CallMediaFrameSealer> {
    try {
      const frameContext = CallMediaFrameContext.of(
        context.callId,
        context.senderId,
      );
      const epoch = CallMediaFrameHeader.epochOf(context.epoch);
      const sealerId = CryptoAdapter.randomBytes(
        CallMediaFrameHeader.SEALER_ID_LENGTH,
      );

      return new CallMediaFrameSealer(
        epoch,
        await CallMediaSealerKey.derive(
          await CallMediaSealerKey.importCallKey(callKey),
          frameContext,
          epoch,
          sealerId,
          'encrypt',
        ),
        sealerId,
      );
    } catch {
      throw new InvalidCallMediaFrameError();
    }
  }

  private constructor(
    epoch: number,
    key: CallMediaSealerKey,
    sealerId: Uint8Array,
  ) {
    this.#epoch = epoch;
    this.#key = key;
    this.#sealerId = sealerId;
  }

  public async seal(frame: Uint8Array, track: string): Promise<Uint8Array> {
    const header = new CallMediaFrameHeader(
      this.#epoch,
      this.#sealerId,
      this.#sequence,
    );

    this.#sequence += 1;

    try {
      return await this.#key.seal(header, track, frame);
    } catch {
      throw new InvalidCallMediaFrameError();
    }
  }
}
