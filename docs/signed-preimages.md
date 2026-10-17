# Signed protocol preimages

The package owns every signed preimage of the Pigeon Swarm public protocol.
Nodes and clients pass domain values to one static class per format and never
assemble signed bytes, digests or domain strings themselves. Each class exposes
`signingContent`, `sign` and `verify`; some formats add a digest or helper. All
preimages are RFC 8785 (JCS) canonical JSON encoded as UTF-8, sometimes behind a
domain prefix. All signatures are Ed25519 and verified strictly.

## Signature encoding

A `Signature` is the 64-byte Ed25519 signature as padded standard base64:
exactly 88 characters, 86 data characters followed by `==`. The 86th character
carries two signature bits and four zero padding bits, so sixteen strings decode
to the same bytes. `Signature` accepts only the canonical one, the text whose
base64 decode and re-encode round trip is unchanged, and throws
`InvalidSignatureError` for the other fifteen. A signature therefore has exactly
one accepted text form, so consumers may key replay guards, record ids and
deduplication on it, and `PublicKey.isValidSignature` never sees another form.

## Canonical JSON

`CanonicalJson.serialize(value)` is the RFC 8785 serializer that every format
uses. It accepts `null`, booleans, safe integers, strings without lone
surrogates, arrays and plain or null-prototype objects up to `MAX_DEPTH` (64)
levels. Object members whose value is `undefined` are omitted. It rejects
non-integer or unsafe numbers, `undefined` array items, lone surrogates, class
instances, functions, symbols and bigints with `InvalidCanonicalJsonError`.

## Formats

| Class                                    | Signed bytes                                                                                                                  | Signer                                                 |
| ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `SignedHttpRequestSignature`             | `'pigeon:signed-http-request:v1\n'` + JCS `{bodyHash, method, path, timestamp}`                                               | identity, device or recovery key                       |
| `IdentitySignature`                      | `'pigeon:identity:v1\n'` + JCS of the identity document without `signature`                                                   | identity key                                           |
| `KeychainSignature`                      | `'pigeon:keychain:v1\n'` + JCS `{encryptedPayload, ownerIdentityId, previousKeychainExternalIdentifier?, timestamp, version}` | owner identity key                                     |
| `DeviceAuthorizationTransitionSignature` | JCS `{domain: 'pigeon:device-authorization:transition:v3', proofOfPossession?, transition}`                                   | author device, or the recovery authority for `recover` |
| proof of possession                      | JCS `{domain: 'pigeon:device-authorization:proof-of-possession:v2', transition}`                                              | target device                                          |
| `DeviceSealedSecretSignature`            | JCS of the sealed secret with `purpose: 'pigeon:device-sealed-secret:v1'`                                                     | publisher device                                       |
| `PublicMutationSignature`                | `'pigeon:public-mutation:v2\n'` + JCS of the mutation without `signature`                                                     | device named by `author.deviceCredential`              |
| `CommunityOperationSignature`            | `'pigeon:community-operation:v1\n'` + record id `community:<id>:op:<digest>`                                                  | actor identity key                                     |
| `CommunityInvitationPossession`          | `'pigeon:community-invitation-possession:v1\n'` + JCS `{communityId, identityId, invitationId, networkId}`                    | invitation key (`CommunityInvitationKey`)              |
| `CommunityInvitationConsent`             | `'pigeon:community-invitation-consent:v1\n'` + JCS `{communityId, identityId, invitationId, networkId}`                       | identity key named by `identityId`                     |

Device pairing messages are described in [device-pairing.md](device-pairing.md).

`verify(document, …, signature, key)` returns nothing or throws the format's
error. When the document names its signer (`authorCredential`,
`targetCredential`, `author.deviceCredential`), `sign` and `verify` also require
the key to be that credential. `PublicMutationSignature.verify(mutation, key)`
returns the strictly parsed, frozen mutation.

Every format has its own versioned domain, either as a `pigeon:…\n` prefix or as
a `domain` or `purpose` member, so a signature made in one context never
verifies in another even when the same key signs both. Plain JCS without a
domain is not accepted for any format.

### Signed HTTP requests

`payload(request)` upper-cases the method (`[A-Z]{1,16}`), requires a path that
starts with `/` (at most 8192 characters) and a safe nonnegative millisecond
timestamp. `bodyHash` is the lowercase hex SHA-256 of the body: bytes as given
for a `Uint8Array`, UTF-8 for a string, `{}` for `null` or `undefined`, and
`JSON.stringify` for an object, exactly as the client serialized it.
`isFresh(timestamp, now)` accepts a skew of `MAX_CLOCK_SKEW_MS` (30 s). The
verifier must remember `replayKey(identityId, signature)` for
`REPLAY_WINDOW_MS` (60 s) and reject repeats; the replay store stays in the
application.

### Identity, keychain and sealed secret documents

Shapes are closed: unknown members and missing required members are rejected.
Identity and identity-scoped ids (`id`, `ownerIdentityId`, `identityId`,
`publisherCredential`, `recipientCredential`) are Ed25519 SPKI PEM bodies;
`deviceCredential` and `recoveryAuthority` are full PEMs. The identity
`deviceCredentialCommitment` must equal `DeviceCredentialCommitment.of` the
device credential, the lowercase hex SHA-256 of its PEM.

### Device authorization transitions

`operation` is `enroll`, `revoke` or `recover`; `revision` is derived as
`previousRevision + 1`. Enrollment and recovery carry a proof of possession
(`provePossession` with the target key); revocation must not. Optional
`compromisedCredentials` hold 1 to `MAX_COMPROMISED_CREDENTIALS` (32) PEMs in
strictly ascending order, each compromised at or before `previousRevision`.

### Public mutations

The body is `{author: {authorizationRevision, deviceCredential, identityId},
frontier?, kind, operationId, payloadDigest, predecessor, recordId, sequence,
store, version: 2}`. `kind` is `put` or `delete`; `operationId` is 22 to 64
base64url characters (`newOperationId()` draws 16 random bytes); text fields hold
at most `MAX_TEXT_LENGTH` (1024) characters; `predecessor` is `null` exactly when
`sequence` is 0. An optional `frontier` holds 1 to `MAX_FRONTIER_HEADS` (64)
strictly ascending digests. `payloadDigest(payload)` and `digest(mutation)` are
the unpadded base64url SHA-256 of the canonical JSON of the record payload and
of the whole signed mutation; a successor names its predecessor by `digest`.
Ordering and conflict resolution stay in the application.

### Community operations and invitations

`CommunityOperationSignature` signs the record id, which already commits to the
community and the operation digest.

An invitation link carries a secret of 32 bytes as 43 characters of canonical
unpadded base64url. `CommunityInvitationKey.fromSecret(secret)` derives the
Ed25519 seed `HKDF-SHA256(ikm = secret, salt = empty, info =
'pigeon:community-invitation-key:v1', L = 32)` and wipes the secret bytes and
the seed; `generate()` returns a fresh `{key, secret}`. The key never
serializes (`toJSON` throws) and signs only possession proofs. `publicKey()`
is the raw 32-byte public key as canonical unpadded base64url, and
`CommunityInvitationKey.parsePublicKey(text)` accepts only that text for a
point that is on the curve, canonically encoded and not of small order.

Both proofs sign `CanonicalJson({communityId, identityId, invitationId,
networkId})` under their own domain:

- `communityId`: 1 to 128 base64url characters;
- `identityId`: the canonical base64 SPKI body of a strict Ed25519 key that is
  not of small order, so an alias of the joiner's key fails;
- `invitationId`: 32 bytes as canonical unpadded base64url;
- `networkId`: a UUID as the `@haskou/value-objects` `UUID` accepts it
  (versions 1 to 8 with variant `8` to `b`, or the nil or max UUID, in either
  case); the proof signs its exact text.

`key.signPossession(fields)` signs
`'pigeon:community-invitation-possession:v1\n'` + the body, and
`CommunityInvitationPossession.verify(fields, possession, invitationKey)`
checks it under the invitation key. `CommunityInvitationConsent.sign(fields,
identityKey)` signs `'pigeon:community-invitation-consent:v1\n'` + the body
only with the key whose SPKI body is `fields.identityId`, and
`CommunityInvitationConsent.verify(fields, consent)` checks it under that id.
`contentOf(fields)` returns either preimage. A proof is the 64-byte Ed25519
signature as 86 characters of canonical unpadded base64url. Verification is
strict RFC 8032: `S >= L`, a non-canonical `R` or key and a small-order key
fail, and no other alphabet, padding or PEM key is read.

### Private freshness requests

`PrivateFreshnessRequest.serialize(input)` builds the exact request JSON that
`PrivateFreshnessProof.verify` expects from `{batchCommitment,
expectedHeadHash, expectedRevision, nonce, scopeId}`, adding `version: 1`; see
[private-freshness-proofs.md](private-freshness-proofs.md).

## Errors

Every failure, including a malformed input that would make a nested parser
throw, surfaces as the format's fixed-message error without input, cause or
nested message: `InvalidSignedHttpRequestError`, `InvalidIdentitySignatureError`,
`InvalidKeychainSignatureError`, `InvalidDeviceAuthorizationTransitionError`,
`InvalidDeviceSealedSecretError`, `InvalidPublicMutationError`,
`InvalidCommunityOperationSignatureError`,
`InvalidCommunityInvitationError`, `InvalidPrivateFreshnessRequestError`
and `InvalidCanonicalJsonError`.

## Vectors

The package publishes its vectors as `@haskou/pigeon-swarm-crypto/vectors/*`.
Consumers load them in their own specs instead of keeping mirrored fixtures:
`canonical-json`, `signed-http-request`, `identity-signature`,
`keychain-signature`, `device-authorization-transition`, `device-sealed-secret`,
`device-pairing`, `call-event`, `community-moderation-log`,
`community-invitation`, `community-operation`, `content-replication`, `conversation-operation` and
`private-freshness-request`. Vector keys are disposable test keys.

## Verification

Unit tests reproduce every vector byte for byte and cover tampering, wrong
signers, non-canonical signatures, closed shapes and bounds. The identity,
keychain and signed-HTTP vectors also reject signatures made without their
domain and signatures replayed from each of the other two domains.
`yarn test:signed-preimages`, after `yarn build`, bundles the public API for
Chromium and checks that Node and the browser produce and accept the same bytes
and signatures for the shipped vectors.
