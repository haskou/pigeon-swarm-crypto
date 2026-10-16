import { InvalidProofOfWorkError } from '../errors/InvalidProofOfWorkError';

export class ProofOfWorkEncoding {
  private static readonly FIELD_PATTERN = /^[\x21-\x7e]+$/;
  private static readonly IDENTITY_ADMISSION_DOMAIN =
    'pigeon-identity-admission:v2';

  private static readonly LENGTH_PREFIX_BYTES = 4;
  private static readonly MAILBOX_CREATION_DOMAIN =
    'pigeon-mailbox-creation:v2';

  private static readonly NONCE_PATTERN = /^(0|[1-9][0-9]*)$/;

  public static readonly MAX_DIFFICULTY_BITS = 32;
  public static readonly MAX_FIELD_LENGTH = 256;
  public static readonly MAX_NETWORK_IDS = 64;
  public static readonly MAX_NONCE_LENGTH = 16;
  public static readonly MIN_DIFFICULTY_BITS = 1;

  private static concat(parts: Uint8Array[]): Uint8Array {
    const bytes = new Uint8Array(
      parts.reduce((length, part) => length + part.length, 0),
    );
    let offset = 0;

    for (const part of parts) {
      bytes.set(part, offset);
      offset += part.length;
    }

    return bytes;
  }

  private static count(value: number): Uint8Array {
    const bytes = new Uint8Array(ProofOfWorkEncoding.LENGTH_PREFIX_BYTES);
    new DataView(bytes.buffer).setUint32(0, value);

    return bytes;
  }

  private static field(value: unknown): Uint8Array {
    if (
      typeof value !== 'string' ||
      value.length > ProofOfWorkEncoding.MAX_FIELD_LENGTH ||
      !ProofOfWorkEncoding.FIELD_PATTERN.test(value)
    ) {
      throw new InvalidProofOfWorkError();
    }

    return ProofOfWorkEncoding.lengthPrefixed(value);
  }

  private static lengthPrefixed(value: string): Uint8Array {
    const bytes = new Uint8Array(
      ProofOfWorkEncoding.LENGTH_PREFIX_BYTES + value.length,
    );
    new DataView(bytes.buffer).setUint32(0, value.length);

    for (let index = 0; index < value.length; index += 1) {
      bytes[ProofOfWorkEncoding.LENGTH_PREFIX_BYTES + index] =
        value.charCodeAt(index);
    }

    return bytes;
  }

  private static networkIds(networkIds: unknown): Uint8Array[] {
    if (
      !Array.isArray(networkIds) ||
      networkIds.length === 0 ||
      networkIds.length > ProofOfWorkEncoding.MAX_NETWORK_IDS ||
      new Set(networkIds).size !== networkIds.length
    ) {
      throw new InvalidProofOfWorkError();
    }

    return [...networkIds]
      .sort()
      .map((networkId) => ProofOfWorkEncoding.field(networkId));
  }

  public static assertDifficulty(difficultyBits: unknown): void {
    if (
      typeof difficultyBits !== 'number' ||
      !Number.isInteger(difficultyBits) ||
      difficultyBits < ProofOfWorkEncoding.MIN_DIFFICULTY_BITS ||
      difficultyBits > ProofOfWorkEncoding.MAX_DIFFICULTY_BITS
    ) {
      throw new InvalidProofOfWorkError();
    }
  }

  public static identityAdmission(
    identityId: unknown,
    networkIds: unknown,
  ): Uint8Array {
    const identity = ProofOfWorkEncoding.field(identityId);
    const networks = ProofOfWorkEncoding.networkIds(networkIds);

    return ProofOfWorkEncoding.concat([
      ProofOfWorkEncoding.lengthPrefixed(
        ProofOfWorkEncoding.IDENTITY_ADMISSION_DOMAIN,
      ),
      identity,
      ProofOfWorkEncoding.count(networks.length),
      ...networks,
    ]);
  }

  public static isNonce(nonce: unknown): nonce is string {
    return (
      typeof nonce === 'string' &&
      nonce.length <= ProofOfWorkEncoding.MAX_NONCE_LENGTH &&
      ProofOfWorkEncoding.NONCE_PATTERN.test(nonce)
    );
  }

  public static leadingZeroBits(digest: Uint8Array): number {
    let bits = 0;
    let counting = true;

    for (const byte of digest) {
      const zeros = Math.clz32(byte) - 24;
      bits += counting ? zeros : 0;
      counting = counting && byte === 0;
    }

    return bits;
  }

  public static mailboxCreation(
    mailboxId: unknown,
    postTokenHash: unknown,
    readTokenHash: unknown,
  ): Uint8Array {
    return ProofOfWorkEncoding.concat([
      ProofOfWorkEncoding.lengthPrefixed(
        ProofOfWorkEncoding.MAILBOX_CREATION_DOMAIN,
      ),
      ProofOfWorkEncoding.field(mailboxId),
      ProofOfWorkEncoding.field(postTokenHash),
      ProofOfWorkEncoding.field(readTokenHash),
    ]);
  }

  public static nonce(nonce: string): Uint8Array {
    return ProofOfWorkEncoding.lengthPrefixed(nonce);
  }
}
