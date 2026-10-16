import { Buffer } from 'buffer';

import { InvalidMlsExtensionError } from './InvalidMlsExtensionError';

/**
 * The roster frontier a commit or welcome is bound to: up to 256 distinct
 * roster-log head digests (unpadded base64url SHA-256), sorted ascending and
 * joined by newlines after a domain prefix. Carried as a commit's
 * authenticated data and as the GroupInfo extension 0xf420.
 */
export class MlsRosterFrontier {
  private static readonly PREFIX = 'pigeon:community-frontier:v1\n';
  private static readonly MAX_HEADS = 256;
  private static readonly MAX_BYTES =
    MlsRosterFrontier.PREFIX.length + MlsRosterFrontier.MAX_HEADS * 44 - 1;

  private static readonly DIGEST = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
  public static readonly EXTENSION_TYPE = 0xf420;

  private static validate(frontier: readonly string[]): readonly string[] {
    if (
      frontier.length > MlsRosterFrontier.MAX_HEADS ||
      !frontier.every(
        (digest, index) =>
          MlsRosterFrontier.DIGEST.test(digest) &&
          (index === 0 || frontier[index - 1] < digest),
      )
    )
      throw new InvalidMlsExtensionError();

    return frontier;
  }

  public static encode(frontier: readonly string[]): Uint8Array {
    const sorted = MlsRosterFrontier.validate(
      [...frontier].sort((left, right) => (left < right ? -1 : 1)),
    );

    return new Uint8Array(
      Buffer.from(MlsRosterFrontier.PREFIX + sorted.join('\n'), 'utf8'),
    );
  }

  public static decode(bytes: Uint8Array): string[] {
    if (bytes.length > MlsRosterFrontier.MAX_BYTES)
      throw new InvalidMlsExtensionError();
    // Every valid byte is ASCII, so any other byte fails the checks below.
    const text = Buffer.from(bytes).toString('latin1');

    if (!text.startsWith(MlsRosterFrontier.PREFIX))
      throw new InvalidMlsExtensionError();
    const body = text.slice(MlsRosterFrontier.PREFIX.length);

    return [...MlsRosterFrontier.validate(body === '' ? [] : body.split('\n'))];
  }
}
