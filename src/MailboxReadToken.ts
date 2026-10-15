import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidMailboxKeyError } from './errors/InvalidMailboxKeyError';
import { BoundedText } from './internal/BoundedText';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { KeyMaterial } from './internal/KeyMaterial';
import { SymmetricKey } from './SymmetricKey';

export class MailboxReadToken {
  private static readonly DEVICE_LABEL = 'pigeon/mailbox/device-read/v1';
  private static readonly LABEL = 'pigeon/mailbox/read/v1';
  private static readonly MAILBOX_ID_LENGTH = 32;
  private static readonly MAX_CREDENTIAL_BYTES = 4096;
  private static readonly TOKEN_LENGTH = 32;

  private static mailboxIdBytes(mailboxId: string): Buffer {
    CanonicalBase64Url.decode(mailboxId, MailboxReadToken.MAILBOX_ID_LENGTH);

    return Buffer.from(mailboxId, 'utf8');
  }

  private static token(rootKey: SymmetricKey, info: Uint8Array): string {
    return CanonicalBase64Url.encode(
      hkdf(
        sha256,
        KeyMaterial.of(rootKey),
        undefined,
        info,
        MailboxReadToken.TOKEN_LENGTH,
      ),
    );
  }

  public static derive(rootKey: SymmetricKey, mailboxId: string): string {
    try {
      return this.token(
        rootKey,
        Buffer.concat([
          Buffer.from(MailboxReadToken.LABEL, 'utf8'),
          this.mailboxIdBytes(mailboxId),
        ]),
      );
    } catch {
      throw new InvalidMailboxKeyError();
    }
  }

  public static deriveDevice(
    rootKey: SymmetricKey,
    mailboxId: string,
    deviceCredential: string,
  ): string {
    try {
      const id = this.mailboxIdBytes(mailboxId);
      const idLength = Buffer.alloc(4);
      idLength.writeUInt32BE(id.length);

      return this.token(
        rootKey,
        Buffer.concat([
          Buffer.from(MailboxReadToken.DEVICE_LABEL, 'utf8'),
          idLength,
          id,
          BoundedText.encode(
            deviceCredential,
            MailboxReadToken.MAX_CREDENTIAL_BYTES,
          ),
        ]),
      );
    } catch {
      throw new InvalidMailboxKeyError();
    }
  }
}
