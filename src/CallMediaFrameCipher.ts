import { gcm } from '@noble/ciphers/aes.js';
import { equalBytes } from '@noble/ciphers/utils.js';
import { Buffer } from 'buffer';

import { InvalidCallMediaFrameError } from './errors/InvalidCallMediaFrameError';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { KeyMaterial } from './internal/KeyMaterial';
import { SymmetricKey } from './SymmetricKey';

export class CallMediaFrameCipher {
  static readonly #MARKER = Uint8Array.of(0x50, 0x53, 0x43, 0x45, 0x31);
  static readonly #MAX_FRAME_BYTES = 8 * 1024 * 1024;
  static readonly #NONCE_LENGTH = 12;
  static readonly #TAG_LENGTH = 16;

  readonly #key: Uint8Array;

  public static fromKey(key: SymmetricKey): CallMediaFrameCipher {
    try {
      return new CallMediaFrameCipher(new Uint8Array(KeyMaterial.of(key)));
    } catch {
      throw new InvalidCallMediaFrameError();
    }
  }

  public static hasMarker(frame: Uint8Array): boolean {
    return (
      frame instanceof Uint8Array &&
      frame.length >= CallMediaFrameCipher.#MARKER.length &&
      equalBytes(
        frame.subarray(0, CallMediaFrameCipher.#MARKER.length),
        CallMediaFrameCipher.#MARKER,
      )
    );
  }

  private constructor(key: Uint8Array) {
    this.#key = key;
  }

  public open(frame: Uint8Array): Uint8Array {
    try {
      const headerLength =
        CallMediaFrameCipher.#MARKER.length +
        CallMediaFrameCipher.#NONCE_LENGTH;

      if (
        !CallMediaFrameCipher.hasMarker(frame) ||
        frame.length < headerLength + CallMediaFrameCipher.#TAG_LENGTH ||
        frame.length >
          CallMediaFrameCipher.#MAX_FRAME_BYTES +
            headerLength +
            CallMediaFrameCipher.#TAG_LENGTH
      )
        throw new InvalidCallMediaFrameError();

      return gcm(
        this.#key,
        frame.subarray(CallMediaFrameCipher.#MARKER.length, headerLength),
      ).decrypt(frame.subarray(headerLength));
    } catch {
      throw new InvalidCallMediaFrameError();
    }
  }

  public seal(frame: Uint8Array): Uint8Array {
    try {
      if (
        !(frame instanceof Uint8Array) ||
        frame.length > CallMediaFrameCipher.#MAX_FRAME_BYTES
      )
        throw new InvalidCallMediaFrameError();
      const nonce = CryptoAdapter.randomBytes(
        CallMediaFrameCipher.#NONCE_LENGTH,
      );

      return Buffer.concat([
        CallMediaFrameCipher.#MARKER,
        nonce,
        gcm(this.#key, nonce).encrypt(frame),
      ]);
    } catch {
      throw new InvalidCallMediaFrameError();
    }
  }
}
