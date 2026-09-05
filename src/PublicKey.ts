import {
  InvalidFormatError,
  InvalidLengthError,
  Media,
  NullObject,
  StringValueObject,
  assert,
} from '@haskou/value-objects';
import { Buffer } from 'buffer';

import { AsymmetricEncryptedPayload } from './AsymmetricEncryptedPayload';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { CryptoPayload } from './internal/CryptoPayload';
import { Key } from './Key';
import { Signature } from './Signature';

export class PublicKey extends Key {
  private static readonly LENGTH = 113;
  private static readonly MAX_PAYLOAD_LENGTH = 1024 * 1024;
  private static readonly PAYLOAD_ALGORITHM = 'x25519-hkdf-sha256-aes-256-gcm';
  private static readonly PAYLOAD_VERSION = 'v2';
  private static readonly PATTERN =
    /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=]+\n-----END PUBLIC KEY-----\n$/;

  private static getPayloadAad(): Buffer {
    return Buffer.from(
      [PublicKey.PAYLOAD_VERSION, PublicKey.PAYLOAD_ALGORITHM].join('.'),
    );
  }

  public static fromPEM(pem: string | StringValueObject): PublicKey {
    return new PublicKey(pem.valueOf());
  }

  constructor(value: string | StringValueObject) {
    super(value?.valueOf());

    if (NullObject.isNullObject(this)) {
      return this;
    }

    this.ensureIsValidPublicKey(this.value);
  }

  private ensureIsValidPublicKey(value: string): void {
    assert(
      value.length === PublicKey.LENGTH,
      new InvalidLengthError(value, PublicKey.LENGTH),
    );
    assert(PublicKey.PATTERN.test(value), new InvalidFormatError(value));
  }

  public isValidSignature(
    payload: CryptoPayload,
    signature: Signature,
  ): boolean {
    const messageBuffer =
      payload instanceof Media
        ? payload.getBuffer()
        : Buffer.from(payload.valueOf());
    const signatureBuffer = Buffer.from(signature.valueOf(), 'base64');

    return CryptoAdapter.verify(signatureBuffer, messageBuffer, this.valueOf());
  }

  public encrypt(payload: CryptoPayload): AsymmetricEncryptedPayload {
    const messageBuffer =
      payload instanceof Media
        ? payload.getBuffer()
        : Buffer.from(payload.valueOf());

    assert(
      messageBuffer.length <= PublicKey.MAX_PAYLOAD_LENGTH,
      new InvalidLengthError(
        messageBuffer.length,
        PublicKey.MAX_PAYLOAD_LENGTH,
      ),
    );

    const x25519Pub = CryptoAdapter.publicKeyToX25519(this.valueOf());
    const ephemeralPriv = CryptoAdapter.x25519RandomPrivateKey();
    const ephemeralPub = CryptoAdapter.x25519PublicKey(ephemeralPriv);
    const sharedSecret = CryptoAdapter.x25519SharedSecret(
      ephemeralPriv,
      x25519Pub,
    );
    const aesKey = CryptoAdapter.deriveEncryptionKeyWithHkdf(
      sharedSecret,
      ephemeralPub,
      x25519Pub,
    );
    const iv = CryptoAdapter.randomBytes(12);
    const { cipherText, tag } = CryptoAdapter.encryptAes256Gcm(
      aesKey,
      iv,
      messageBuffer,
      PublicKey.getPayloadAad(),
    );

    return new AsymmetricEncryptedPayload(
      [
        PublicKey.PAYLOAD_VERSION,
        PublicKey.PAYLOAD_ALGORITHM,
        Buffer.from(ephemeralPub).toString('base64'),
        iv.toString('base64'),
        Buffer.from(cipherText).toString('base64'),
        Buffer.from(tag).toString('base64'),
      ].join('.'),
    );
  }
}
