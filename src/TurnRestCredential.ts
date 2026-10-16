import { Buffer } from 'buffer';

import { InvalidTurnCredentialError } from './errors/InvalidTurnCredentialError';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { TurnRestCredentialPair } from './TurnRestCredentialPair';

export class TurnRestCredential {
  private static readonly MAX_SHARED_SECRET_LENGTH = 4096;
  private static readonly PEER_ID_PATTERN = /^[\x21-\x7e]{1,256}$/;
  private static readonly SUBJECT_LABEL = 'pigeon.turn.subject.v2\0';
  private static readonly SUBJECT_LENGTH = 32;
  private static readonly USER_PATTERN = /^[\x21-\x39\x3b-\x7e]{1,512}$/;

  private static secretBytes(sharedSecret: unknown): Uint8Array {
    if (
      typeof sharedSecret !== 'string' ||
      sharedSecret.length === 0 ||
      sharedSecret.length > this.MAX_SHARED_SECRET_LENGTH ||
      /[\uD800-\uDFFF]/u.test(sharedSecret)
    )
      throw new InvalidTurnCredentialError();

    return Buffer.from(sharedSecret);
  }

  public static issue(
    sharedSecret: string,
    expiresAtSeconds: number,
    user: string,
  ): TurnRestCredentialPair {
    const secret = this.secretBytes(sharedSecret);

    if (
      !Number.isSafeInteger(expiresAtSeconds) ||
      expiresAtSeconds <= 0 ||
      typeof user !== 'string' ||
      !this.USER_PATTERN.test(user)
    )
      throw new InvalidTurnCredentialError();
    const username = `${expiresAtSeconds}:${user}`;

    return Object.freeze({
      credential: Buffer.from(
        CryptoAdapter.hmacSha1(secret, Buffer.from(username)),
      ).toString('base64'),
      username,
    });
  }

  public static peerSubject(sharedSecret: string, peerId: string): string {
    const secret = this.secretBytes(sharedSecret);

    if (typeof peerId !== 'string' || !this.PEER_ID_PATTERN.test(peerId))
      throw new InvalidTurnCredentialError();

    return Buffer.from(
      CryptoAdapter.hmacSha256(
        secret,
        Buffer.from(`${this.SUBJECT_LABEL}${peerId}`),
      ),
    )
      .toString('hex')
      .slice(0, this.SUBJECT_LENGTH);
  }
}
