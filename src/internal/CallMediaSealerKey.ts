import { Buffer } from 'buffer';

import { InvalidCallMediaFrameError } from '../errors/InvalidCallMediaFrameError';
import { SymmetricKey } from '../SymmetricKey';
import { CallMediaFrameContext } from './CallMediaFrameContext';
import { CallMediaFrameHeader } from './CallMediaFrameHeader';
import { KeyMaterial } from './KeyMaterial';

export class CallMediaSealerKey {
  static readonly #ALGORITHM = 'AES-GCM';
  static readonly #KEY_LABEL = 'pigeon/call-media-frame/v2/key';
  static readonly #MAX_FRAME_BYTES = 8 * 1024 * 1024;
  static readonly #NONCE_BITS = 96;
  static readonly #NONCE_LABEL = 'pigeon/call-media-frame/v2/nonce';
  static readonly #NONCE_MODULUS =
    BigInt(2) ** BigInt(CallMediaSealerKey.#NONCE_BITS);

  static readonly #TAG_LENGTH = 16;

  readonly #key: CryptoKey;
  readonly #nonceBase: bigint;

  private static hkdf(info: Uint8Array): HkdfParams {
    return {
      hash: 'SHA-256',
      info: info as Uint8Array<ArrayBuffer>,
      name: 'HKDF',
      salt: new Uint8Array(),
    };
  }

  public static importCallKey(key: SymmetricKey): Promise<CryptoKey> {
    const material = KeyMaterial.of(key) as Uint8Array<ArrayBuffer>;

    return globalThis.crypto.subtle
      .importKey('raw', material, 'HKDF', false, ['deriveBits', 'deriveKey'])
      .finally(() => material.fill(0));
  }

  public static async derive(
    callKey: CryptoKey,
    context: CallMediaFrameContext,
    epoch: number,
    sealerId: Uint8Array,
    usage: 'decrypt' | 'encrypt',
  ): Promise<CallMediaSealerKey> {
    const [key, nonceBase] = await Promise.all([
      globalThis.crypto.subtle.deriveKey(
        CallMediaSealerKey.hkdf(
          context.info(CallMediaSealerKey.#KEY_LABEL, epoch, sealerId),
        ),
        callKey,
        { length: 256, name: CallMediaSealerKey.#ALGORITHM },
        false,
        [usage],
      ),
      globalThis.crypto.subtle.deriveBits(
        CallMediaSealerKey.hkdf(
          context.info(CallMediaSealerKey.#NONCE_LABEL, epoch, sealerId),
        ),
        callKey,
        CallMediaSealerKey.#NONCE_BITS,
      ),
    ]);

    return new CallMediaSealerKey(
      key,
      BigInt(`0x${Buffer.from(nonceBase).toString('hex')}`),
    );
  }

  private constructor(key: CryptoKey, nonceBase: bigint) {
    this.#key = key;
    this.#nonceBase = nonceBase;
  }

  private nonce(sequence: number): Uint8Array<ArrayBuffer> {
    return new Uint8Array(
      Buffer.from(
        (
          (this.#nonceBase + BigInt(sequence)) %
          CallMediaSealerKey.#NONCE_MODULUS
        )
          .toString(16)
          .padStart(CallMediaSealerKey.#NONCE_BITS / 4, '0'),
        'hex',
      ),
    );
  }

  public async open(
    header: CallMediaFrameHeader,
    track: string,
    frame: Uint8Array,
  ): Promise<Uint8Array> {
    if (
      frame.length <
        CallMediaFrameHeader.LENGTH + CallMediaSealerKey.#TAG_LENGTH ||
      frame.length >
        CallMediaFrameHeader.LENGTH +
          CallMediaSealerKey.#TAG_LENGTH +
          CallMediaSealerKey.#MAX_FRAME_BYTES
    )
      throw new InvalidCallMediaFrameError();

    return new Uint8Array(
      await globalThis.crypto.subtle.decrypt(
        {
          additionalData: header.additionalData(track),
          iv: this.nonce(header.sequence),
          name: CallMediaSealerKey.#ALGORITHM,
        },
        this.#key,
        frame.subarray(CallMediaFrameHeader.LENGTH) as Uint8Array<ArrayBuffer>,
      ),
    );
  }

  public async seal(
    header: CallMediaFrameHeader,
    track: string,
    frame: Uint8Array,
  ): Promise<Uint8Array> {
    if (
      !(frame instanceof Uint8Array) ||
      frame.length > CallMediaSealerKey.#MAX_FRAME_BYTES
    )
      throw new InvalidCallMediaFrameError();
    const ciphertext = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        {
          additionalData: header.additionalData(track),
          iv: this.nonce(header.sequence),
          name: CallMediaSealerKey.#ALGORITHM,
        },
        this.#key,
        frame as Uint8Array<ArrayBuffer>,
      ),
    );
    const sealed = new Uint8Array(
      CallMediaFrameHeader.LENGTH + ciphertext.length,
    );

    sealed.set(header.bytes());
    sealed.set(ciphertext, CallMediaFrameHeader.LENGTH);

    return sealed;
  }
}
