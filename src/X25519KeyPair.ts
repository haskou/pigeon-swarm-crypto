import { Buffer } from 'buffer';

import { InvalidX25519KeyError } from './errors/InvalidX25519KeyError';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { X25519Envelope } from './internal/X25519Envelope';
import { X25519EncryptedPayload } from './X25519EncryptedPayload';
import { X25519PublicKey } from './X25519PublicKey';

export class X25519KeyPair {
  private static readonly LENGTH = 32;

  readonly #privateKey: Uint8Array;
  readonly #publicKey: X25519PublicKey;

  public static generate(): X25519KeyPair {
    return new X25519KeyPair(CryptoAdapter.x25519RandomPrivateKey());
  }

  public static fromPrivateKey(privateKey: Uint8Array): X25519KeyPair {
    if (privateKey.length !== X25519KeyPair.LENGTH)
      throw new InvalidX25519KeyError();

    return new X25519KeyPair(Uint8Array.from(privateKey));
  }

  private constructor(privateKey: Uint8Array) {
    this.#privateKey = privateKey;
    this.#publicKey = X25519PublicKey.fromRaw(
      CryptoAdapter.x25519PublicKey(privateKey),
    );
  }

  public getPublicKey(): X25519PublicKey {
    return this.#publicKey;
  }

  public decrypt(payload: X25519EncryptedPayload): Buffer {
    return X25519Envelope.open(
      this.#privateKey,
      this.#publicKey.toRaw(),
      payload.valueOf(),
    );
  }
}
