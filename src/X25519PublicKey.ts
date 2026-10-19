import { Media } from '@haskou/value-objects';
import { Buffer } from 'buffer';

import { InvalidX25519KeyError } from './errors/InvalidX25519KeyError';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { CryptoPayload } from './internal/CryptoPayload';
import { X25519Envelope } from './internal/X25519Envelope';
import { X25519EncryptedPayload } from './X25519EncryptedPayload';

export class X25519PublicKey {
  private static readonly LENGTH = 32;

  readonly #raw: Uint8Array;

  public static fromRaw(raw: Uint8Array): X25519PublicKey {
    if (
      raw.length !== X25519PublicKey.LENGTH ||
      !CryptoAdapter.isCanonicalX25519PublicKey(raw)
    )
      throw new InvalidX25519KeyError();

    return new X25519PublicKey(Uint8Array.from(raw));
  }

  private constructor(raw: Uint8Array) {
    this.#raw = raw;
  }

  public toRaw(): Uint8Array {
    return Uint8Array.from(this.#raw);
  }

  public encrypt(payload: CryptoPayload): X25519EncryptedPayload {
    const plaintext =
      payload instanceof Media
        ? payload.getBuffer()
        : Buffer.from(payload.valueOf());

    return new X25519EncryptedPayload(
      X25519Envelope.seal(this.#raw, plaintext),
    );
  }
}
