import { CanonicalBase64Url } from './CanonicalBase64Url';
import { CryptoAdapter } from './CryptoAdapter';

export class RelayRecordEncoding {
  private static readonly MAX_ADDRESS_LENGTH = 2048;
  private static readonly PEER_ID_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{1,128}$/;
  private static readonly PUBLIC_KEY_PREFIX = Uint8Array.of(8, 1, 18, 32);

  public static isAddressList(value: unknown, maxLength: number): boolean {
    return (
      Array.isArray(value) &&
      value.length > 0 &&
      value.length <= maxLength &&
      value.every(
        (address) =>
          typeof address === 'string' &&
          address.length > 0 &&
          address.length <= this.MAX_ADDRESS_LENGTH &&
          !/[\uD800-\uDFFF]/u.test(address),
      )
    );
  }

  public static hasSignedRecordFields(value: unknown): boolean {
    if (typeof value !== 'object' || value === null) return false;
    const record = value as Record<string, unknown>;

    return (
      this.isLifetime(record.issuedAt, record.expiresAt) &&
      this.isPeerId(record.peerId) &&
      this.isPublicKey(record.publicKey)
    );
  }

  public static isLifetime(issuedAt: unknown, expiresAt: unknown): boolean {
    return (
      Number.isSafeInteger(issuedAt) &&
      Number.isSafeInteger(expiresAt) &&
      (issuedAt as number) >= 0 &&
      (issuedAt as number) < (expiresAt as number)
    );
  }

  public static isPeerId(value: unknown): boolean {
    return typeof value === 'string' && this.PEER_ID_PATTERN.test(value);
  }

  public static isPublicKey(value: unknown): boolean {
    try {
      const protobuf = CanonicalBase64Url.decode(value, 36);

      return (
        CryptoAdapter.equalBytes(
          protobuf.subarray(0, this.PUBLIC_KEY_PREFIX.length),
          this.PUBLIC_KEY_PREFIX,
        ) &&
        CryptoAdapter.isStrictEd25519PublicKey(
          protobuf.subarray(this.PUBLIC_KEY_PREFIX.length),
        )
      );
    } catch {
      return false;
    }
  }

  public static verify(
    signature: unknown,
    message: Uint8Array,
    publicKey: string,
  ): boolean {
    return CryptoAdapter.verify(
      CanonicalBase64Url.decode(signature, 64),
      message,
      CanonicalBase64Url.decode(publicKey, 36).subarray(
        this.PUBLIC_KEY_PREFIX.length,
      ),
    );
  }
}
