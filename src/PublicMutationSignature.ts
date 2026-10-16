import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import type { PublicMutation } from './PublicMutation';
import type { PublicMutationBody } from './PublicMutationBody';

import { CanonicalJson } from './CanonicalJson';
import { InvalidPublicMutationError } from './errors/InvalidPublicMutationError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

/**
 * Device-signed proof that one public record was mutated: kind, scope,
 * author, causal position and the digest of the immutable payload.
 */
export class PublicMutationSignature {
  private static readonly DOMAIN = 'pigeon:public-mutation:v2\n';
  private static readonly OPERATION_ID = /^[A-Za-z0-9_-]{22,64}$/;
  private static readonly OPERATION_ID_BYTES = 16;
  private static readonly BODY_FIELDS = [
    'author',
    'kind',
    'operationId',
    'payloadDigest',
    'predecessor',
    'recordId',
    'sequence',
    'store',
    'version',
  ];

  public static readonly MAX_TEXT_LENGTH = 1024;
  public static readonly MAX_FRONTIER_HEADS = 64;

  private static text(value: unknown): string {
    return PreimageFields.text(value, this.MAX_TEXT_LENGTH);
  }

  private static frontier(value: unknown): string[] {
    const heads = PreimageFields.list(
      value,
      (head) => PreimageFields.pattern(head, PreimageFields.DIGEST),
      1,
    );
    PreimageFields.check(
      heads.length <= this.MAX_FRONTIER_HEADS &&
        heads.every((head, index) => index === 0 || heads[index - 1] < head),
    );

    return heads;
  }

  private static body(record: Record<string, unknown>): PublicMutationBody {
    const author = PreimageFields.record(record.author, [
      'authorizationRevision',
      'deviceCredential',
      'identityId',
    ]);
    const sequence = PreimageFields.counter(record.sequence);
    const predecessor =
      record.predecessor === null
        ? null
        : PreimageFields.pattern(record.predecessor, PreimageFields.DIGEST);
    PreimageFields.check((predecessor === null) === (sequence === 0));
    PreimageFields.check(record.kind === 'put' || record.kind === 'delete');

    return {
      author: {
        authorizationRevision: PreimageFields.counter(
          author.authorizationRevision,
        ),
        deviceCredential: this.text(author.deviceCredential),
        identityId: this.text(author.identityId),
      },
      frontier: PreimageFields.optional(record.frontier, (value) =>
        this.frontier(value),
      ),
      kind: record.kind as PublicMutationBody['kind'],
      operationId: PreimageFields.pattern(
        record.operationId,
        this.OPERATION_ID,
      ),
      payloadDigest: PreimageFields.pattern(
        record.payloadDigest,
        PreimageFields.DIGEST,
      ),
      predecessor,
      recordId: this.text(record.recordId),
      sequence,
      store: this.text(record.store),
      version: PreimageFields.literal(record.version, 2),
    };
  }

  private static content(body: PublicMutationBody): string {
    return (
      this.DOMAIN +
      CanonicalJson.serialize(
        this.body(PreimageFields.record(body, this.BODY_FIELDS, ['frontier'])),
      )
    );
  }

  private static parsed(value: unknown): PublicMutation {
    const record = PreimageFields.record(
      value,
      [...this.BODY_FIELDS, 'signature'],
      ['frontier'],
    );

    return Object.freeze({
      ...this.body(record),
      signature: PreimageFields.signature(record.signature),
    });
  }

  private static hash(value: unknown): string {
    return CanonicalBase64Url.encode(
      sha256(Buffer.from(CanonicalJson.serialize(value), 'utf8')),
    );
  }

  /** A fresh random operation id: 16 bytes as unpadded base64url. */
  public static newOperationId(): string {
    return CanonicalBase64Url.encode(
      CryptoAdapter.randomBytes(this.OPERATION_ID_BYTES),
    );
  }

  /** Unpadded base64url SHA-256 of the canonical JSON of a record payload. */
  public static payloadDigest(payload: unknown): string {
    return PreimageFields.guarded(InvalidPublicMutationError, () =>
      this.hash(payload),
    );
  }

  /** Strict decoder: unknown, missing or malformed fields are rejected. */
  public static parse(value: unknown): PublicMutation {
    return PreimageFields.guarded(InvalidPublicMutationError, () =>
      this.parsed(value),
    );
  }

  /** Identifier of one exact signed mutation, used as a predecessor. */
  public static digest(mutation: PublicMutation): string {
    return PreimageFields.guarded(InvalidPublicMutationError, () =>
      this.hash(this.parsed(mutation)),
    );
  }

  public static signingContent(body: PublicMutationBody): string {
    return PreimageFields.guarded(InvalidPublicMutationError, () =>
      this.content(body),
    );
  }

  /** Signs with the device key whose PEM body is `author.deviceCredential`. */
  public static sign(
    body: PublicMutationBody,
    key: PrivateKey,
  ): PublicMutation {
    return PreimageFields.guarded(InvalidPublicMutationError, () => {
      const content = this.content(body);

      return this.parsed({
        ...body,
        signature: PreimageFields.signFor(
          content,
          key,
          body.author.deviceCredential,
        ).valueOf(),
      });
    });
  }

  /** Verifies the device signature and returns the strictly parsed mutation. */
  public static verify(
    mutation: PublicMutation,
    key: PublicKey,
  ): PublicMutation {
    return PreimageFields.guarded(InvalidPublicMutationError, () => {
      const parsed = this.parsed(mutation);
      const { signature, ...body } = parsed;
      PreimageFields.verifyFor(
        this.content(body),
        new Signature(signature),
        key,
        parsed.author.deviceCredential,
      );

      return parsed;
    });
  }
}
