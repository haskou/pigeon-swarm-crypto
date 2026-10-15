import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import type { SignedHttpRequest } from './SignedHttpRequest';
import type { SignedHttpRequestPayload } from './SignedHttpRequestPayload';

import { CanonicalJson } from './CanonicalJson';
import { InvalidSignedHttpRequestError } from './errors/InvalidSignedHttpRequestError';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

export class SignedHttpRequestSignature {
  private static readonly METHOD = /^[A-Z]{1,16}$/;
  private static readonly MAX_PATH_LENGTH = 8192;
  public static readonly MAX_CLOCK_SKEW_MS = 30_000;
  public static readonly REPLAY_WINDOW_MS = 60_000;

  private static bodyBytes(body: unknown): Uint8Array {
    if (body instanceof Uint8Array) return body;

    if (typeof body === 'string') return Buffer.from(body, 'utf8');

    if (body === undefined || body === null) return Buffer.from('{}', 'utf8');
    PreimageFields.check(typeof body === 'object');

    return Buffer.from(JSON.stringify(body), 'utf8');
  }

  public static payload(request: SignedHttpRequest): SignedHttpRequestPayload {
    return PreimageFields.guarded(InvalidSignedHttpRequestError, () => {
      const method = PreimageFields.pattern(
        PreimageFields.text(request.method).toUpperCase(),
        this.METHOD,
      );
      const path = PreimageFields.text(request.path, this.MAX_PATH_LENGTH);
      PreimageFields.check(path.startsWith('/'));

      return Object.freeze({
        bodyHash: Buffer.from(sha256(this.bodyBytes(request.body))).toString(
          'hex',
        ),
        method,
        path,
        timestamp: PreimageFields.counter(request.timestamp),
      });
    });
  }

  public static signingContent(request: SignedHttpRequest): string {
    return PreimageFields.guarded(InvalidSignedHttpRequestError, () =>
      CanonicalJson.serialize(this.payload(request)),
    );
  }

  public static sign(request: SignedHttpRequest, key: PrivateKey): Signature {
    return PreimageFields.guarded(InvalidSignedHttpRequestError, () =>
      key.sign(this.signingContent(request)),
    );
  }

  public static verify(
    request: SignedHttpRequest,
    signature: Signature,
    key: PublicKey,
  ): void {
    PreimageFields.guarded(InvalidSignedHttpRequestError, () =>
      PreimageFields.verify(this.signingContent(request), signature, key),
    );
  }

  public static isFresh(timestamp: number, now: number): boolean {
    return (
      Number.isSafeInteger(timestamp) &&
      Number.isSafeInteger(now) &&
      Math.abs(now - timestamp) <= this.MAX_CLOCK_SKEW_MS
    );
  }

  public static replayKey(identityId: string, signature: Signature): string {
    return `${identityId}:${signature.valueOf()}`;
  }
}
