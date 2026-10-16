import { equalBytes } from '@noble/ciphers/utils.js';

import { InvalidCallMediaFrameError } from './errors/InvalidCallMediaFrameError';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { KeyMaterial } from './internal/KeyMaterial';
import { SymmetricKey } from './SymmetricKey';

export class CallMediaFrameCipher {
  static readonly #ALGORITHM = 'AES-GCM';
  static readonly #MARKER = Uint8Array.of(0x50, 0x53, 0x43, 0x45, 0x31);
  static readonly #MAX_FRAME_BYTES = 8 * 1024 * 1024;
  static readonly #NONCE_LENGTH = 12;
  static readonly #TAG_LENGTH = 16;
  static readonly #HEADER_LENGTH =
    CallMediaFrameCipher.#MARKER.length + CallMediaFrameCipher.#NONCE_LENGTH;

  readonly #key: CryptoKey;

  public static async fromKey(
    key: SymmetricKey,
  ): Promise<CallMediaFrameCipher> {
    let material: Uint8Array<ArrayBuffer> | undefined;

    try {
      material = KeyMaterial.of(key) as Uint8Array<ArrayBuffer>;

      return new CallMediaFrameCipher(
        await globalThis.crypto.subtle.importKey(
          'raw',
          material,
          CallMediaFrameCipher.#ALGORITHM,
          false,
          ['decrypt', 'encrypt'],
        ),
      );
    } catch {
      throw new InvalidCallMediaFrameError();
    } finally {
      material?.fill(0);
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

  private constructor(key: CryptoKey) {
    this.#key = key;
  }

  public async open(frame: Uint8Array): Promise<Uint8Array> {
    try {
      if (
        !CallMediaFrameCipher.hasMarker(frame) ||
        frame.length <
          CallMediaFrameCipher.#HEADER_LENGTH +
            CallMediaFrameCipher.#TAG_LENGTH ||
        frame.length >
          CallMediaFrameCipher.#MAX_FRAME_BYTES +
            CallMediaFrameCipher.#HEADER_LENGTH +
            CallMediaFrameCipher.#TAG_LENGTH
      )
        throw new InvalidCallMediaFrameError();

      return new Uint8Array(
        await globalThis.crypto.subtle.decrypt(
          {
            iv: frame.subarray(
              CallMediaFrameCipher.#MARKER.length,
              CallMediaFrameCipher.#HEADER_LENGTH,
            ) as Uint8Array<ArrayBuffer>,
            name: CallMediaFrameCipher.#ALGORITHM,
          },
          this.#key,
          frame.subarray(
            CallMediaFrameCipher.#HEADER_LENGTH,
          ) as Uint8Array<ArrayBuffer>,
        ),
      );
    } catch {
      throw new InvalidCallMediaFrameError();
    }
  }

  public async seal(frame: Uint8Array): Promise<Uint8Array> {
    try {
      if (
        !(frame instanceof Uint8Array) ||
        frame.length > CallMediaFrameCipher.#MAX_FRAME_BYTES
      )
        throw new InvalidCallMediaFrameError();
      const nonce = CryptoAdapter.randomBytes(
        CallMediaFrameCipher.#NONCE_LENGTH,
      ) as Uint8Array<ArrayBuffer>;
      const ciphertext = new Uint8Array(
        await globalThis.crypto.subtle.encrypt(
          { iv: nonce, name: CallMediaFrameCipher.#ALGORITHM },
          this.#key,
          frame as Uint8Array<ArrayBuffer>,
        ),
      );
      const sealed = new Uint8Array(
        CallMediaFrameCipher.#HEADER_LENGTH + ciphertext.length,
      );

      sealed.set(CallMediaFrameCipher.#MARKER);
      sealed.set(nonce, CallMediaFrameCipher.#MARKER.length);
      sealed.set(ciphertext, CallMediaFrameCipher.#HEADER_LENGTH);

      return sealed;
    } catch {
      throw new InvalidCallMediaFrameError();
    }
  }
}
