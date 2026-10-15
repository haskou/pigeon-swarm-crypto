import type { Cipher } from '@noble/ciphers/utils.js';

import { gcm } from '@noble/ciphers/aes.js';
import { Buffer } from 'buffer';

import { InvalidMailboxEnvelopeError } from './errors/InvalidMailboxEnvelopeError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { KeyMaterial } from './internal/KeyMaterial';
import { MailboxInboxKeys } from './MailboxInboxKeys';

export class MailboxEnvelope {
  private static readonly ENVELOPE_ID_LENGTH = 16;
  private static readonly IV_LENGTH = 12;
  private static readonly LENGTH_PREFIX_LENGTH = 4;
  private static readonly MAILBOX_ID_LENGTH = 32;
  private static readonly TAG_LENGTH = 16;

  public static readonly BUCKETS: readonly number[] = Object.freeze([
    1024, 4096, 16384, 65536,
  ]);

  public static readonly MAX_PLAINTEXT_BYTES = 65504;

  private static cipher(
    keys: Pick<MailboxInboxKeys, 'envelopeKey' | 'mailboxId'>,
    envelopeId: string,
    iv: Uint8Array,
  ): Cipher {
    CanonicalBase64Url.decode(
      keys.mailboxId,
      MailboxEnvelope.MAILBOX_ID_LENGTH,
    );
    CanonicalBase64Url.decode(envelopeId, MailboxEnvelope.ENVELOPE_ID_LENGTH);

    return gcm(
      KeyMaterial.ofBytes(keys.envelopeKey),
      iv,
      Buffer.from(`${keys.mailboxId}.${envelopeId}`, 'utf8'),
    );
  }

  private static frameLength(bucket: number): number {
    return bucket - MailboxEnvelope.IV_LENGTH - MailboxEnvelope.TAG_LENGTH;
  }

  public static bucketFor(plaintextLength: number): number {
    const bucket = MailboxEnvelope.BUCKETS.find(
      (size) =>
        this.frameLength(size) >=
        MailboxEnvelope.LENGTH_PREFIX_LENGTH + plaintextLength,
    );

    if (
      !Number.isSafeInteger(plaintextLength) ||
      plaintextLength < 0 ||
      bucket === undefined
    )
      throw new InvalidMailboxEnvelopeError();

    return bucket;
  }

  public static seal(
    keys: Pick<MailboxInboxKeys, 'envelopeKey' | 'mailboxId'>,
    envelopeId: string,
    plaintext: Uint8Array,
  ): string {
    try {
      if (!(plaintext instanceof Uint8Array))
        throw new InvalidMailboxEnvelopeError();
      const framed = Buffer.alloc(
        this.frameLength(this.bucketFor(plaintext.length)),
      );
      framed.writeUInt32BE(plaintext.length);
      framed.set(plaintext, MailboxEnvelope.LENGTH_PREFIX_LENGTH);
      const iv = CryptoAdapter.randomBytes(MailboxEnvelope.IV_LENGTH);

      return CanonicalBase64Url.encode(
        Buffer.concat([iv, this.cipher(keys, envelopeId, iv).encrypt(framed)]),
      );
    } catch {
      throw new InvalidMailboxEnvelopeError();
    }
  }

  public static open(
    keys: Pick<MailboxInboxKeys, 'envelopeKey' | 'mailboxId'>,
    envelopeId: string,
    body: string,
  ): Uint8Array {
    try {
      const bucket = MailboxEnvelope.BUCKETS.find(
        (size) =>
          typeof body === 'string' && body.length === Math.ceil((size * 4) / 3),
      );

      if (bucket === undefined) throw new InvalidMailboxEnvelopeError();
      const sealed = CanonicalBase64Url.decode(body, bucket);
      const framed = Buffer.from(
        this.cipher(
          keys,
          envelopeId,
          sealed.subarray(0, MailboxEnvelope.IV_LENGTH),
        ).decrypt(sealed.subarray(MailboxEnvelope.IV_LENGTH)),
      );
      const end = MailboxEnvelope.LENGTH_PREFIX_LENGTH + framed.readUInt32BE(0);

      if (
        end > framed.length ||
        framed.subarray(end).some((byte) => byte !== 0)
      )
        throw new InvalidMailboxEnvelopeError();

      return framed.subarray(MailboxEnvelope.LENGTH_PREFIX_LENGTH, end);
    } catch {
      throw new InvalidMailboxEnvelopeError();
    }
  }
}
