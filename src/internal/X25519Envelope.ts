import { InvalidLengthError, assert } from '@haskou/value-objects';
import { concatBytes } from '@noble/hashes/utils.js';
import { Buffer } from 'buffer';

import { InvalidX25519EncryptedPayloadError } from '../errors/InvalidX25519EncryptedPayloadError';
import { InvalidX25519KeyError } from '../errors/InvalidX25519KeyError';
import { CanonicalBase64Url } from './CanonicalBase64Url';
import { CryptoAdapter } from './CryptoAdapter';

const SCHEME = 'pigeon-x25519-seal';
const VERSION = 'v1';
const LABEL = `${SCHEME}.${VERSION}`;
const LABEL_BYTES = Buffer.from(LABEL);
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const MAX_PLAINTEXT_LENGTH = 64 * 1024;
const encodedLength = (bytes: number): number => Math.ceil((bytes * 4) / 3);
const MAX_ENVELOPE_LENGTH =
  LABEL.length +
  1 +
  encodedLength(KEY_LENGTH) +
  1 +
  encodedLength(NONCE_LENGTH) +
  1 +
  encodedLength(MAX_PLAINTEXT_LENGTH) +
  1 +
  encodedLength(TAG_LENGTH);

export class X25519Envelope {
  private static parse(envelope: unknown): {
    cipherText: Uint8Array;
    ephemeralPublicKey: Uint8Array;
    nonce: Uint8Array;
    tag: Uint8Array;
  } {
    if (typeof envelope !== 'string' || envelope.length > MAX_ENVELOPE_LENGTH)
      throw new InvalidX25519EncryptedPayloadError();
    const parts = envelope.split('.');

    if (parts.length !== 6 || parts[0] !== SCHEME || parts[1] !== VERSION)
      throw new InvalidX25519EncryptedPayloadError();
    const [, , ephemeral, nonce, cipherText, tag] = parts;

    return {
      cipherText: CanonicalBase64Url.decodeBounded(
        cipherText,
        MAX_PLAINTEXT_LENGTH,
      ),
      ephemeralPublicKey: CanonicalBase64Url.decode(ephemeral, KEY_LENGTH),
      nonce: CanonicalBase64Url.decode(nonce, NONCE_LENGTH),
      tag: CanonicalBase64Url.decode(tag, TAG_LENGTH),
    };
  }

  private static recipientSharedSecret(
    privateKey: Uint8Array,
    publicKey: Uint8Array,
  ): Uint8Array {
    try {
      return CryptoAdapter.x25519SharedSecret(privateKey, publicKey);
    } catch {
      throw new InvalidX25519KeyError();
    }
  }

  public static open(
    privateKey: Uint8Array,
    publicKey: Uint8Array,
    envelope: unknown,
  ): Buffer {
    try {
      const { cipherText, ephemeralPublicKey, nonce, tag } =
        this.parse(envelope);
      const key = CryptoAdapter.deriveX25519SealKey(
        CryptoAdapter.x25519SharedSecret(privateKey, ephemeralPublicKey),
        ephemeralPublicKey,
        publicKey,
        LABEL_BYTES,
      );

      return CryptoAdapter.decryptAes256Gcm(
        key,
        nonce,
        cipherText,
        tag,
        concatBytes(LABEL_BYTES, ephemeralPublicKey),
      );
    } catch {
      throw new InvalidX25519EncryptedPayloadError();
    }
  }

  public static seal(
    recipientPublicKey: Uint8Array,
    plaintext: Uint8Array,
  ): string {
    assert(
      plaintext.length <= MAX_PLAINTEXT_LENGTH,
      new InvalidLengthError(plaintext.length, MAX_PLAINTEXT_LENGTH),
    );
    const ephemeralPrivateKey = CryptoAdapter.x25519RandomPrivateKey();
    const ephemeralPublicKey =
      CryptoAdapter.x25519PublicKey(ephemeralPrivateKey);
    const key = CryptoAdapter.deriveX25519SealKey(
      this.recipientSharedSecret(ephemeralPrivateKey, recipientPublicKey),
      ephemeralPublicKey,
      recipientPublicKey,
      LABEL_BYTES,
    );
    const nonce = CryptoAdapter.randomBytes(NONCE_LENGTH);
    const { cipherText, tag } = CryptoAdapter.encryptAes256Gcm(
      key,
      nonce,
      plaintext,
      concatBytes(LABEL_BYTES, ephemeralPublicKey),
    );

    return [
      SCHEME,
      VERSION,
      CanonicalBase64Url.encode(ephemeralPublicKey),
      CanonicalBase64Url.encode(nonce),
      CanonicalBase64Url.encode(cipherText),
      CanonicalBase64Url.encode(tag),
    ].join('.');
  }
}
