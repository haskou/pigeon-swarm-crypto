# Commitment ids and state digests

`CommitmentId` derives the content-addressed identifiers that Pigeon Swarm
nodes and clients must compute identically, and `StateDigest` derives the
digests nodes use to compare replicated state. Every output is byte-identical
across Node and browsers and is pinned by
`@haskou/pigeon-swarm-crypto/vectors/commitment-ids.json`.

## Interface

```ts
CommitmentId.call(creatorIdentityId, nonce);
CommitmentId.community(networkId, ownerIdentityId, nonce);
CommitmentId.communityChannel(communityId, creatorIdentityId, createdAt);
CommitmentId.communityRole(communityId, creatorIdentityId, createdAt);
CommitmentId.communityRequest(
  communityId,
  type,
  creatorIdentityId,
  identityId,
  createdAt,
);
CommitmentId.communityModerationLog(
  communityId,
  actorIdentityId,
  action,
  targetType,
  targetId,
  createdAt,
);
CommitmentId.communityInviteToken(
  communityId,
  creatorIdentityId,
  nonce,
  maxUses,
  expiresAt,
);
CommitmentId.mlsRecord({ epoch, groupId, kind, payload, recipientIdentityId });
CommitmentId.privateBlobOwner(saltHex, identityId);
CommitmentId.privateBlobOwnerSalt();
CommitmentId.oneToOneConversation(firstIdentityId, secondIdentityId, networkId);
CommitmentId.groupConversation(creatorIdentityId, networkId, nonce);
CommitmentId.invitation(inviterIdentityId, recipientIdentityId, nonce, subjectId?);
CommitmentId.groupMessage(authorIdentityId);
CommitmentId.isGroupMessageOf(id, authorIdentityId);

StateDigest.of(plainObject);
StateDigest.ofBytes(bytes);
StateDigest.communityFrontiers([{ communityId, frontier }]);
```

## Formats

JSON below means `JSON.stringify` of the listed array. RFC 8785 means JSON
Canonicalization Scheme bytes. base64url is unpadded.

| Method                           | Output                                                                                                                                                        |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `call`                           | First 16 bytes of `sha256(creator ":" nonce)` with byte 6 set to `(byte mod 16) + 128` and byte 8 to `(byte mod 64) + 128`, as an 8-4-4-4-12 lowercase hex id |
| `community`                      | base64url SHA-256 of RFC 8785 `{networkId, nonce, ownerIdentityId}`                                                                                           |
| `communityChannel`               | First 24 hex characters of SHA-256 of JSON `["channel", communityId, creatorIdentityId, createdAt]`                                                           |
| `communityRole`                  | First 24 hex characters of SHA-256 of JSON `["role", communityId, creatorIdentityId, createdAt]`                                                              |
| `communityRequest`               | First 24 hex characters of SHA-256 of JSON `[communityId, type, creatorIdentityId, identityId, createdAt]`                                                    |
| `communityModerationLog`         | First 24 hex characters of SHA-256 of JSON `[communityId, actorIdentityId, action, targetType, targetId, createdAt]`                                          |
| `communityInviteToken`           | base64url SHA-256 of JSON `[communityId, creatorIdentityId, nonce, maxUses, expiresAt or null]`                                                               |
| `mlsRecord`                      | base64url SHA-256 of RFC 8785 `{epoch?, groupId, kind, payload, recipientIdentityId?}`                                                                        |
| `privateBlobOwner`               | Lowercase hex HMAC-SHA256 keyed by the 32-byte salt over the UTF-8 identity id                                                                                |
| `oneToOneConversation`           | `one-to-one:` and lowercase hex SHA-256 of `a ":" b ":" networkId`, with the two identity ids sorted by UTF-16 code unit                                      |
| `groupConversation`              | `group:` and base64url SHA-256 of RFC 8785 `{creatorIdentityId, networkId, nonce}`                                                                            |
| `invitation`                     | `invitation:` and lowercase hex SHA-256 of RFC 8785 `{inviterIdentityId, nonce, recipientIdentityId, subjectId?}`                                             |
| `groupMessage`                   | `nonce "." tag`: a random 16-byte nonce and the first 16 bytes of SHA-256 of `"pigeon-group-message-id" 0x00 author 0x00 nonce`, both base64url               |
| `StateDigest.of`                 | base64url SHA-256 of RFC 8785 of the object                                                                                                                   |
| `StateDigest.ofBytes`            | base64url SHA-256 of the bytes                                                                                                                                |
| `StateDigest.communityFrontiers` | base64url SHA-256 of JSON `[[communityId, heads]]`, communities and heads sorted by UTF-16 code unit                                                          |

All hashed text is UTF-8. Changing any of these formats changes persisted or
replicated identifiers, so a change requires a new versioned format.

## Validation

Every failure throws `InvalidCommitmentError` with a fixed message and no input.

- Text arguments must be non-empty strings without lone surrogates.
- Timestamps, counters, `maxUses`, `expiresAt` and `epoch` must be
  nonnegative safe integers. `expiresAt` may be omitted; `null` is rejected.
- The call nonce must match `^[A-Za-z0-9_-]{16,128}$`, so it cannot contain
  the `:` delimiter.
- `communityRequest` accepts only the `invitation` and `request` types.
- `mlsRecord` accepts a plain object with only the five listed fields. An
  undefined optional field and an empty `recipientIdentityId` are omitted from
  the preimage.
- `oneToOneConversation` identity ids must not contain the `:` delimiter.
- `invitation` omits an undefined `subjectId` from the preimage.
- `isGroupMessageOf` returns `false` for any id of another author, a tag of
  another nonce, a non-canonical or padded part, a missing or extra part, or a
  malformed author; it never throws.
- The `groupMessage` tag is not a MAC: it stops another author reusing an id
  already published under someone else's identity, but it does not prove
  authorship. Authorship comes from the signature on the message.
- `privateBlobOwner` requires a 64-character lowercase hex salt. Each node
  creates one salt with `privateBlobOwnerSalt` and keeps it secret, so owner
  keys cannot be linked to identity ids by anyone without the salt.
- `StateDigest.of` accepts only plain objects of JSON data: no `NaN`,
  infinities, `BigInt`, functions, symbols, class instances, `undefined` array
  items or cycles, and at most 64 levels of nesting. Undefined properties are
  dropped, as in JSON.
- `communityFrontiers` entries must be exactly `{communityId, frontier}` with
  text heads, and each community may appear only once.

## Vectors

Each section of `vectors/commitment-ids.json` lists `valid` cases with the
arguments, the exact preimage and the id, and `invalid` cases that must throw.
`mlsRecord.distinct` shows non-canonical preimages that must never produce the
listed id. Lone-surrogate cases are covered by the package tests rather than the
file, because strict JSON parsers reject them.
