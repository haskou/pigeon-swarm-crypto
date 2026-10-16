import { Buffer } from 'buffer';

import { CallMediaFramePeer } from './CallMediaFramePeer';
import { InvalidCallMediaFrameError } from './errors/InvalidCallMediaFrameError';
import { CallMediaEpoch } from './internal/CallMediaEpoch';
import { CallMediaFrameContext } from './internal/CallMediaFrameContext';
import { CallMediaFrameHeader } from './internal/CallMediaFrameHeader';
import { CallMediaReplayWindow } from './internal/CallMediaReplayWindow';
import { CallMediaSealer } from './internal/CallMediaSealer';
import { CallMediaSealerKey } from './internal/CallMediaSealerKey';
import { PreimageFields } from './internal/PreimageFields';
import { SymmetricKey } from './SymmetricKey';

export class CallMediaFrameOpener {
  static readonly #MAX_EPOCHS = 2;
  static readonly #MAX_SEALERS_PER_EPOCH = 64;

  readonly #context: CallMediaFrameContext;
  readonly #epochs = new Map<number, CallMediaEpoch>();
  #latestEpoch = -1;

  public static create(peer: CallMediaFramePeer): CallMediaFrameOpener {
    return new CallMediaFrameOpener(
      PreimageFields.guarded(InvalidCallMediaFrameError, () =>
        CallMediaFrameContext.of(peer.callId, peer.senderId),
      ),
    );
  }

  private constructor(context: CallMediaFrameContext) {
    this.#context = context;
  }

  private dropEpochsBefore(epoch: number): void {
    for (const held of this.#epochs.keys())
      if (held < epoch) this.#epochs.delete(held);
  }

  private async sealerOf(
    held: CallMediaEpoch,
    header: CallMediaFrameHeader,
    sealerId: string,
  ): Promise<CallMediaSealer> {
    const known = held.sealers.get(sealerId);

    if (known) return known;

    if (held.sealers.size >= CallMediaFrameOpener.#MAX_SEALERS_PER_EPOCH)
      throw new InvalidCallMediaFrameError();

    return {
      key: await CallMediaSealerKey.derive(
        await held.callKey,
        this.#context,
        header.epoch,
        header.sealerId,
        'decrypt',
      ),
      window: new CallMediaReplayWindow(),
    };
  }

  private retain(
    held: CallMediaEpoch,
    sealer: CallMediaSealer,
    sealerId: string,
    sequence: number,
  ): void {
    const retained = held.sealers.get(sealerId);

    if (retained) return retained.window.accept(sequence);

    if (held.sealers.size >= CallMediaFrameOpener.#MAX_SEALERS_PER_EPOCH)
      throw new InvalidCallMediaFrameError();
    sealer.window.accept(sequence);
    held.sealers.set(sealerId, sealer);
  }

  public async addKey(callKey: SymmetricKey, epoch: number): Promise<void> {
    if (
      !(callKey instanceof SymmetricKey) ||
      CallMediaFrameHeader.epochOf(epoch) <= this.#latestEpoch
    )
      throw new InvalidCallMediaFrameError();
    const held: CallMediaEpoch = {
      callKey: CallMediaSealerKey.importCallKey(callKey),
      sealers: new Map(),
    };

    this.#latestEpoch = epoch;
    this.#epochs.set(epoch, held);

    if (this.#epochs.size > CallMediaFrameOpener.#MAX_EPOCHS)
      this.#epochs.delete(Math.min(...this.#epochs.keys()));

    try {
      await held.callKey;
    } catch {
      this.#epochs.delete(epoch);
      throw new InvalidCallMediaFrameError();
    }
  }

  public async open(frame: Uint8Array, track: string): Promise<Uint8Array> {
    try {
      const header = CallMediaFrameHeader.read(frame);
      const held = this.#epochs.get(header.epoch);
      const sealerId = Buffer.from(header.sealerId).toString('hex');

      if (!held) throw new InvalidCallMediaFrameError();
      const sealer = await this.sealerOf(held, header, sealerId);

      if (!sealer.window.admits(header.sequence))
        throw new InvalidCallMediaFrameError();
      const plaintext = await sealer.key.open(header, track, frame);

      if (this.#epochs.get(header.epoch) !== held)
        throw new InvalidCallMediaFrameError();
      this.retain(held, sealer, sealerId, header.sequence);

      if (header.epoch === Math.max(...this.#epochs.keys()))
        this.dropEpochsBefore(header.epoch);

      return plaintext;
    } catch {
      throw new InvalidCallMediaFrameError();
    }
  }
}
