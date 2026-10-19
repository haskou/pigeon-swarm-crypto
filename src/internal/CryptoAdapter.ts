import { gcm } from '@noble/ciphers/aes.js';
import { equalBytes } from '@noble/ciphers/utils.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha512 } from '@noble/hashes/sha2.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
} from '@noble/hashes/utils.js';
import { Buffer } from 'buffer';

import { InvalidEd25519PublicKeyError } from '../errors/InvalidEd25519PublicKeyError';
import { HashAlgorithm } from './HashAlgorithm';

const privateKeyDerPrefix = hexToBytes('302e020100300506032b657004220420');
const publicKeyDerPrefix = hexToBytes('302a300506032b6570032100');
const gcmTagLength = 16;
const asymmetricPayloadV2Info = Buffer.from(
  '@haskou/value-objects/asymmetric-payload/v2',
);

export class CryptoAdapter {
  private static pemToDer(pem: string): Buffer {
    const base64 = pem
      .replace(/-----BEGIN (?:PRIVATE|PUBLIC) KEY-----/, '')
      .replace(/-----END (?:PRIVATE|PUBLIC) KEY-----/, '')
      .replace(/\s/g, '');

    return Buffer.from(base64, 'base64');
  }

  private static parseEd25519PublicKeyPem(
    publicKeyPem: string,
  ): Uint8Array | undefined {
    const match =
      /^-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=]+)\n-----END PUBLIC KEY-----\n$/.exec(
        publicKeyPem,
      );

    if (match === null) {
      return undefined;
    }

    const base64 = match[1];
    const der = Buffer.from(base64, 'base64');

    if (
      der.toString('base64') !== base64 ||
      der.length !== publicKeyDerPrefix.length + 32 ||
      !equalBytes(
        der.subarray(0, publicKeyDerPrefix.length),
        publicKeyDerPrefix,
      )
    ) {
      return undefined;
    }

    return der.subarray(publicKeyDerPrefix.length);
  }

  private static wrapPem(
    label: 'PRIVATE KEY' | 'PUBLIC KEY',
    der: Uint8Array,
  ): string {
    return `-----BEGIN ${label}-----\n${Buffer.from(der).toString('base64')}\n-----END ${label}-----\n`;
  }

  public static decryptAes256Gcm(
    key: Uint8Array,
    iv: Uint8Array,
    cipherText: Uint8Array,
    tag: Uint8Array,
    aad?: Uint8Array,
  ): Buffer {
    const decrypted = gcm(key, iv, aad).decrypt(concatBytes(cipherText, tag));

    return Buffer.from(
      decrypted.buffer as ArrayBuffer,
      decrypted.byteOffset,
      decrypted.byteLength,
    );
  }

  public static deriveEncryptionKeyWithHkdf(
    sharedSecret: Uint8Array,
    ephemeralPublicKey: Uint8Array,
    recipientPublicKey: Uint8Array,
  ): Uint8Array {
    return hkdf(
      sha256,
      sharedSecret,
      concatBytes(ephemeralPublicKey, recipientPublicKey),
      asymmetricPayloadV2Info,
      32,
    );
  }

  public static deriveX25519SealKey(
    sharedSecret: Uint8Array,
    ephemeralPublicKey: Uint8Array,
    recipientPublicKey: Uint8Array,
    info: Uint8Array,
  ): Uint8Array {
    return hkdf(
      sha256,
      sharedSecret,
      concatBytes(ephemeralPublicKey, recipientPublicKey),
      info,
      32,
    );
  }

  public static encryptAes256Gcm(
    key: Uint8Array,
    iv: Uint8Array,
    message: Uint8Array,
    aad?: Uint8Array,
  ): { cipherText: Uint8Array; tag: Uint8Array } {
    const encrypted = gcm(key, iv, aad).encrypt(message);

    return {
      cipherText: encrypted.subarray(0, -gcmTagLength),
      tag: encrypted.subarray(-gcmTagLength),
    };
  }

  public static getPublicKey(privateKeyPem: string): string {
    return this.publicKeyToPem(
      ed25519.getPublicKey(this.privateKeyToSeed(privateKeyPem)),
    );
  }

  public static getRawPublicKey(privateKeyPem: string): Uint8Array {
    return ed25519.getPublicKey(this.privateKeyToSeed(privateKeyPem));
  }

  public static equalBytes(left: Uint8Array, right: Uint8Array): boolean {
    return equalBytes(left, right);
  }

  public static hash(
    algorithm: HashAlgorithm,
    value: string | Uint8Array,
  ): string {
    const bytes = this.toBytes(value);
    const hash = {
      sha256,
      sha512,
    }[algorithm];

    return bytesToHex(hash(bytes));
  }

  public static hkdfSha256(
    inputKeyMaterial: Uint8Array,
    info: string,
    length: number,
  ): Uint8Array {
    return hkdf(sha256, inputKeyMaterial, undefined, Buffer.from(info), length);
  }

  public static hmacSha1(key: Uint8Array, message: Uint8Array): Uint8Array {
    return hmac(sha1, key, message);
  }

  public static hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
    return hmac(sha256, key, message);
  }

  public static isStrictEd25519PublicKey(publicKey: Uint8Array): boolean {
    try {
      return !ed25519.Point.fromBytes(publicKey, false).isSmallOrder();
    } catch {
      return false;
    }
  }

  public static privateKeyToPem(seed: Uint8Array): string {
    return this.wrapPem('PRIVATE KEY', concatBytes(privateKeyDerPrefix, seed));
  }

  public static privateKeyToSeed(privateKeyPem: string): Uint8Array {
    return this.pemToDer(privateKeyPem).subarray(privateKeyDerPrefix.length);
  }

  public static privateKeyToX25519(privateKeyPem: string): Uint8Array {
    return ed25519.utils.toMontgomerySecret(
      this.privateKeyToSeed(privateKeyPem),
    );
  }

  public static publicKeyToPem(publicKey: Uint8Array): string {
    return this.wrapPem(
      'PUBLIC KEY',
      concatBytes(publicKeyDerPrefix, publicKey),
    );
  }

  public static publicKeyToX25519(publicKeyPem: string): Uint8Array {
    return ed25519.utils.toMontgomery(this.publicKeyToBytes(publicKeyPem));
  }

  public static publicKeyToBytes(publicKeyPem: string): Uint8Array {
    const key = this.parseEd25519PublicKeyPem(publicKeyPem);

    if (key === undefined) {
      throw new InvalidEd25519PublicKeyError();
    }

    return key;
  }

  public static publicKeyToStrictBytes(publicKeyPem: string): Uint8Array {
    return this.parseEd25519PublicKeyPem(publicKeyPem) ?? new Uint8Array();
  }

  public static randomBytes(size: number): Buffer {
    return Buffer.from(randomBytes(size));
  }

  public static randomPrivateKeyPem(): string {
    return this.privateKeyToPem(ed25519.utils.randomSecretKey());
  }

  public static sign(message: Uint8Array, privateKeyPem: string): Buffer {
    return Buffer.from(
      ed25519.sign(message, this.privateKeyToSeed(privateKeyPem)),
    );
  }

  public static toBytes(value: string | Uint8Array): Uint8Array {
    if (value instanceof Uint8Array) {
      return value;
    }

    return Buffer.from(value);
  }

  public static verify(
    signature: Uint8Array,
    message: Uint8Array,
    publicKey: string | Uint8Array,
  ): boolean {
    const key =
      typeof publicKey === 'string'
        ? this.publicKeyToStrictBytes(publicKey)
        : publicKey;

    try {
      return ed25519.verify(signature, message, key, { zip215: false });
    } catch {
      return false;
    }
  }

  public static x25519PublicKey(privateKey: Uint8Array): Uint8Array {
    return x25519.getPublicKey(privateKey);
  }

  public static x25519SharedSecret(
    privateKey: Uint8Array,
    publicKey: Uint8Array,
  ): Uint8Array {
    return x25519.getSharedSecret(privateKey, publicKey);
  }

  public static x25519RandomPrivateKey(): Uint8Array {
    return x25519.utils.randomSecretKey();
  }
}
