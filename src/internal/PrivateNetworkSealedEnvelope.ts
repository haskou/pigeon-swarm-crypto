import { concatBytes } from '@noble/hashes/utils.js';

import { CanonicalBase64Url } from './CanonicalBase64Url';
import { CryptoAdapter } from './CryptoAdapter';

export class PrivateNetworkSealedEnvelope {
  private static readonly NONCE_LENGTH = 12;
  private static readonly TAG_LENGTH = 16;
  private static readonly VERSION = 2;

  private static parse(
    envelope: unknown,
    maxPlaintextLength: number,
  ): { ciphertext: string; nonce: string } {
    const maxCiphertextLength = Math.ceil(
      ((maxPlaintextLength + this.TAG_LENGTH) * 4) / 3,
    );

    if (
      typeof envelope !== 'string' ||
      envelope.length > maxCiphertextLength + 64
    )
      throw new Error('Invalid sealed envelope');
    const parsed: unknown = JSON.parse(envelope);
    const { ciphertext, nonce, version } = (parsed ?? {}) as Record<
      string,
      unknown
    >;

    if (
      typeof ciphertext !== 'string' ||
      typeof nonce !== 'string' ||
      version !== this.VERSION ||
      JSON.stringify({ ciphertext, nonce, version }) !== envelope
    )
      throw new Error('Invalid sealed envelope');

    return { ciphertext, nonce };
  }

  public static open(
    key: Uint8Array,
    aad: Uint8Array,
    envelope: unknown,
    maxPlaintextLength: number,
  ): Uint8Array {
    const parsed = this.parse(envelope, maxPlaintextLength);
    const sealedLength = Math.floor((parsed.ciphertext.length * 3) / 4);

    if (
      sealedLength < this.TAG_LENGTH ||
      sealedLength > maxPlaintextLength + this.TAG_LENGTH
    )
      throw new Error('Invalid sealed envelope');
    const sealed = CanonicalBase64Url.decode(parsed.ciphertext, sealedLength);

    return CryptoAdapter.decryptAes256Gcm(
      key,
      CanonicalBase64Url.decode(parsed.nonce, this.NONCE_LENGTH),
      sealed.subarray(0, sealed.length - this.TAG_LENGTH),
      sealed.subarray(sealed.length - this.TAG_LENGTH),
      aad,
    );
  }

  public static seal(
    key: Uint8Array,
    aad: Uint8Array,
    plaintext: Uint8Array,
  ): string {
    const nonce = CryptoAdapter.randomBytes(this.NONCE_LENGTH);
    const { cipherText, tag } = CryptoAdapter.encryptAes256Gcm(
      key,
      nonce,
      plaintext,
      aad,
    );

    return JSON.stringify({
      ciphertext: CanonicalBase64Url.encode(concatBytes(cipherText, tag)),
      nonce: CanonicalBase64Url.encode(nonce),
      version: this.VERSION,
    });
  }
}
