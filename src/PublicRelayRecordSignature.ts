import { InvalidPublicRelayRecordError } from './errors/InvalidPublicRelayRecordError';
import { RelayRecordEncoding } from './internal/RelayRecordEncoding';
import { PublicRelayRecordFields } from './PublicRelayRecordFields';

export class PublicRelayRecordSignature {
  private static readonly MAX_MULTIADDRS = 64;

  public static signingBytes(fields: PublicRelayRecordFields): Uint8Array {
    if (
      !RelayRecordEncoding.hasSignedRecordFields(fields) ||
      !RelayRecordEncoding.isAddressList(
        fields.multiaddrs,
        this.MAX_MULTIADDRS,
      ) ||
      fields.role !== 'relay' ||
      fields.version !== 1
    )
      throw new InvalidPublicRelayRecordError();

    return new TextEncoder().encode(
      JSON.stringify({
        expiresAt: fields.expiresAt,
        issuedAt: fields.issuedAt,
        multiaddrs: [...fields.multiaddrs].sort(),
        peerId: fields.peerId,
        publicKey: fields.publicKey,
        role: fields.role,
        version: fields.version,
      }),
    );
  }

  public static verify(
    fields: PublicRelayRecordFields,
    signature: string,
  ): void {
    const message = this.signingBytes(fields);

    try {
      if (!RelayRecordEncoding.verify(signature, message, fields.publicKey))
        throw new InvalidPublicRelayRecordError();
    } catch {
      throw new InvalidPublicRelayRecordError();
    }
  }
}
