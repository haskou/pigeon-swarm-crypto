import { Buffer } from 'buffer';

import { CallRelayRecordFields } from './CallRelayRecordFields';
import { InvalidCallRelayRecordError } from './errors/InvalidCallRelayRecordError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { RelayRecordEncoding } from './internal/RelayRecordEncoding';

export class CallRelayRecordSignature {
  private static readonly MAX_URLS = 8;

  private static canonicalPayload(fields: CallRelayRecordFields): string {
    if (
      !RelayRecordEncoding.hasSignedRecordFields(fields) ||
      fields.role !== 'call-relay' ||
      !RelayRecordEncoding.isAddressList(fields.urls, this.MAX_URLS) ||
      (fields.version !== 1 && fields.version !== 2)
    )
      throw new InvalidCallRelayRecordError();

    return JSON.stringify({
      expiresAt: fields.expiresAt,
      issuedAt: fields.issuedAt,
      peerId: fields.peerId,
      publicKey: fields.publicKey,
      role: fields.role,
      urls: [...fields.urls].sort(),
      version: fields.version,
    });
  }

  private static hmac(payload: string, sharedSecret: unknown): string {
    if (typeof sharedSecret !== 'string' || sharedSecret.length === 0)
      throw new InvalidCallRelayRecordError();

    return CanonicalBase64Url.encode(
      CryptoAdapter.hmacSha256(Buffer.from(sharedSecret), Buffer.from(payload)),
    );
  }

  public static poolSignature(
    fields: CallRelayRecordFields,
    sharedSecret: string,
  ): string {
    const payload = this.canonicalPayload(fields);

    return fields.version === 2 ? '' : this.hmac(payload, sharedSecret);
  }

  public static signingBytes(fields: CallRelayRecordFields): Uint8Array {
    return new TextEncoder().encode(this.canonicalPayload(fields));
  }

  public static verify(
    fields: CallRelayRecordFields,
    poolSignature: string,
    signature: string,
    sharedSecret: string,
  ): void {
    const payload = this.canonicalPayload(fields);

    try {
      const expectedPoolSignature =
        fields.version === 2 ? '' : this.hmac(payload, sharedSecret);

      if (
        typeof poolSignature !== 'string' ||
        !CryptoAdapter.equalBytes(
          Buffer.from(poolSignature),
          Buffer.from(expectedPoolSignature),
        ) ||
        !RelayRecordEncoding.verify(
          signature,
          Buffer.from(payload),
          fields.publicKey,
        )
      )
        throw new InvalidCallRelayRecordError();
    } catch {
      throw new InvalidCallRelayRecordError();
    }
  }
}
