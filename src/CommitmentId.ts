import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  bytesToHex,
  hexToBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/hashes/utils.js';

import { InvalidCommitmentError } from './errors/InvalidCommitmentError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CommitmentInput } from './internal/CommitmentInput';
import { StrictCanonicalJson } from './internal/StrictCanonicalJson';
import { MlsRecordContent } from './MlsRecordContent';

export class CommitmentId {
  private static readonly callNonce = /^[A-Za-z0-9_-]{16,128}$/;
  private static readonly groupMessageId =
    /^([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{22})$/;

  private static readonly groupMessagePurpose = 'pigeon-group-message-id';
  private static readonly groupMessageNonceBytes = 16;
  private static readonly salt = /^[0-9a-f]{64}$/;
  private static readonly mlsRecordFields = [
    'epoch',
    'groupId',
    'kind',
    'payload',
    'recipientIdentityId',
  ];

  private static shortId(values: (string | number)[]): string {
    return bytesToHex(sha256(utf8ToBytes(JSON.stringify(values)))).slice(0, 24);
  }

  private static longId(preimage: string): string {
    return CanonicalBase64Url.encode(sha256(utf8ToBytes(preimage)));
  }

  private static groupMessageTag(author: string, nonce: string): string {
    return CanonicalBase64Url.encode(
      sha256(
        utf8ToBytes(`${this.groupMessagePurpose}\u0000${author}\u0000${nonce}`),
      ).slice(0, this.groupMessageNonceBytes),
    );
  }

  public static call(creatorIdentityId: string, nonce: string): string {
    if (typeof nonce !== 'string' || !this.callNonce.test(nonce))
      throw new InvalidCommitmentError();
    const creator = CommitmentInput.text(creatorIdentityId);
    const bytes = sha256(utf8ToBytes(`${creator}:${nonce}`)).slice(0, 16);
    bytes[6] = (bytes[6] % 16) + 128;
    bytes[8] = (bytes[8] % 64) + 128;
    const hex = bytesToHex(bytes);

    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20),
    ].join('-');
  }

  public static community(
    networkId: string,
    ownerIdentityId: string,
    nonce: string,
  ): string {
    return this.longId(
      StrictCanonicalJson.serialize({
        networkId: CommitmentInput.text(networkId),
        nonce: CommitmentInput.text(nonce),
        ownerIdentityId: CommitmentInput.text(ownerIdentityId),
      }),
    );
  }

  public static communityChannel(
    communityId: string,
    creatorIdentityId: string,
    createdAt: number,
  ): string {
    return this.shortId([
      'channel',
      CommitmentInput.text(communityId),
      CommitmentInput.text(creatorIdentityId),
      CommitmentInput.counter(createdAt),
    ]);
  }

  public static communityRole(
    communityId: string,
    creatorIdentityId: string,
    createdAt: number,
  ): string {
    return this.shortId([
      'role',
      CommitmentInput.text(communityId),
      CommitmentInput.text(creatorIdentityId),
      CommitmentInput.counter(createdAt),
    ]);
  }

  public static communityRequest(
    communityId: string,
    type: 'invitation' | 'request',
    creatorIdentityId: string,
    identityId: string,
    createdAt: number,
  ): string {
    if (type !== 'invitation' && type !== 'request')
      throw new InvalidCommitmentError();

    return this.shortId([
      CommitmentInput.text(communityId),
      type,
      CommitmentInput.text(creatorIdentityId),
      CommitmentInput.text(identityId),
      CommitmentInput.counter(createdAt),
    ]);
  }

  public static communityModerationLog(
    communityId: string,
    actorIdentityId: string,
    action: string,
    targetType: string,
    targetId: string,
    createdAt: number,
  ): string {
    return this.shortId([
      CommitmentInput.text(communityId),
      CommitmentInput.text(actorIdentityId),
      CommitmentInput.text(action),
      CommitmentInput.text(targetType),
      CommitmentInput.text(targetId),
      CommitmentInput.counter(createdAt),
    ]);
  }

  public static mlsRecord(content: MlsRecordContent): string {
    if (
      typeof content !== 'object' ||
      content === null ||
      Array.isArray(content) ||
      Object.keys(content).some((key) => !this.mlsRecordFields.includes(key))
    )
      throw new InvalidCommitmentError();
    const { epoch, groupId, kind, payload, recipientIdentityId } = content;
    const record: Record<string, unknown> = {
      groupId: CommitmentInput.text(groupId),
      kind: CommitmentInput.text(kind),
      payload: CommitmentInput.text(payload),
    };

    if (epoch !== undefined) record.epoch = CommitmentInput.counter(epoch);

    if (recipientIdentityId !== undefined && recipientIdentityId !== '')
      record.recipientIdentityId = CommitmentInput.text(recipientIdentityId);

    return this.longId(StrictCanonicalJson.serialize(record));
  }

  public static privateBlobOwnerSalt(): string {
    return bytesToHex(randomBytes(32));
  }

  public static privateBlobOwner(salt: string, identityId: string): string {
    if (typeof salt !== 'string' || !this.salt.test(salt))
      throw new InvalidCommitmentError();

    return bytesToHex(
      hmac(
        sha256,
        hexToBytes(salt),
        utf8ToBytes(CommitmentInput.text(identityId)),
      ),
    );
  }

  /** Both participants derive the same id whatever the argument order. */
  public static oneToOneConversation(
    firstIdentityId: string,
    secondIdentityId: string,
    networkId: string,
  ): string {
    const participants = [firstIdentityId, secondIdentityId].map((value) => {
      const identityId = CommitmentInput.text(value);

      if (identityId.includes(':')) throw new InvalidCommitmentError();

      return identityId;
    });
    const network = CommitmentInput.text(networkId);

    return `one-to-one:${bytesToHex(
      sha256(utf8ToBytes(`${participants.sort().join(':')}:${network}`)),
    )}`;
  }

  public static groupConversation(
    creatorIdentityId: string,
    networkId: string,
    nonce: string,
  ): string {
    return `group:${this.longId(
      StrictCanonicalJson.serialize({
        creatorIdentityId: CommitmentInput.text(creatorIdentityId),
        networkId: CommitmentInput.text(networkId),
        nonce: CommitmentInput.text(nonce),
      }),
    )}`;
  }

  public static invitation(
    inviterIdentityId: string,
    recipientIdentityId: string,
    nonce: string,
    subjectId?: string,
  ): string {
    const record: Record<string, unknown> = {
      inviterIdentityId: CommitmentInput.text(inviterIdentityId),
      nonce: CommitmentInput.text(nonce),
      recipientIdentityId: CommitmentInput.text(recipientIdentityId),
    };

    if (subjectId !== undefined)
      record.subjectId = CommitmentInput.text(subjectId);

    return `invitation:${bytesToHex(
      sha256(utf8ToBytes(StrictCanonicalJson.serialize(record))),
    )}`;
  }

  /** A fresh message id whose tag binds it to its author. */
  public static groupMessage(authorIdentityId: string): string {
    const author = CommitmentInput.text(authorIdentityId);
    const nonce = CanonicalBase64Url.encode(
      randomBytes(this.groupMessageNonceBytes),
    );

    return `${nonce}.${this.groupMessageTag(author, nonce)}`;
  }

  /** False for any malformed id or author; never throws. */
  public static isGroupMessageOf(
    id: string,
    authorIdentityId: string,
  ): boolean {
    try {
      const author = CommitmentInput.text(authorIdentityId);
      const [, nonce, tag] = this.groupMessageId.exec(id as string) ?? [];
      CanonicalBase64Url.decode(nonce, this.groupMessageNonceBytes);

      return tag === this.groupMessageTag(author, nonce);
    } catch {
      return false;
    }
  }
}
