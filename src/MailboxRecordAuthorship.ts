import { equalBytes } from '@noble/ciphers/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidMailboxRecordAuthorshipError } from './errors/InvalidMailboxRecordAuthorshipError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { KeyMaterial } from './internal/KeyMaterial';
import { StrictCanonicalJson } from './internal/StrictCanonicalJson';
import { SymmetricKey } from './SymmetricKey';

export class MailboxRecordAuthorship {
  private static readonly LABEL = 'pigeon/mailbox/own-record/v2';
  private static readonly TAG_LENGTH = 32;

  private static compute(
    rootKey: SymmetricKey,
    record: Readonly<Record<string, unknown>>,
  ): Uint8Array {
    const canonical = StrictCanonicalJson.serialize(record);
    StrictCanonicalJson.parse(canonical);
    const tagKey = hkdf(
      sha256,
      KeyMaterial.of(rootKey),
      undefined,
      Buffer.from(MailboxRecordAuthorship.LABEL, 'utf8'),
      MailboxRecordAuthorship.TAG_LENGTH,
    );

    return hmac(sha256, tagKey, Buffer.from(canonical, 'utf8'));
  }

  public static tag(
    rootKey: SymmetricKey,
    record: Readonly<Record<string, unknown>>,
  ): string {
    try {
      return CanonicalBase64Url.encode(this.compute(rootKey, record));
    } catch {
      throw new InvalidMailboxRecordAuthorshipError();
    }
  }

  public static verify(
    rootKey: SymmetricKey,
    record: Readonly<Record<string, unknown>>,
    tag: string,
  ): boolean {
    try {
      return equalBytes(
        this.compute(rootKey, record),
        CanonicalBase64Url.decode(tag, MailboxRecordAuthorship.TAG_LENGTH),
      );
    } catch {
      return false;
    }
  }
}
