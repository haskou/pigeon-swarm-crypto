# Private freshness proofs

`PrivateFreshnessProof` signs and verifies the version 1 challenge-bound
authorization proof defined by Pigeon Swarm's private-delivery contract. It binds
one locally generated request nonce and outbound batch commitment to the exact
authorization scope, revision and head observed by the freshness authority.

## Interface

```ts
const signedProof = PrivateFreshnessProof.sign(unsignedProofJson, authorityKey);

const canonicalProof = PrivateFreshnessProof.verify(
  receivedProofJson,
  trustedCheckpoint.policy.freshnessAuthorityKey,
  outstandingRequestJson,
);
```

The expected signer key comes from the locally trusted authorization checkpoint,
never from the proof itself. Verification requires exact equality between the
proof and request scope, nonce, revision, head and batch commitment. All fields,
including the signer key, are covered by Ed25519 under the UTF-8 domain separator
`pigeon.private-freshness.v1` followed by one zero byte and RFC 8785 JCS bytes.

Inputs use the package's strict JSON boundary: closed shapes, no duplicate
properties, canonical unpadded base64url, 32-byte identifiers and keys, safe
nonnegative revisions, bounded size, depth and token count, and strict Ed25519
verification. Every failure is `InvalidPrivateFreshnessProofError` with no input,
nested parser exception or cause.

## Application responsibilities

This stateless API does not decide whether the checkpoint is current. The caller
must create the 32-byte nonce from a cryptographically secure random source, store
the complete outstanding request locally, accept its nonce once, and reject a
response received more than ten seconds after the local monotonic request start.
It must also reject rollback below any locally observed revision and independently
recompute the batch commitment from verified signed operations.

The request and proof contain private scope metadata. Keep them inside the
participant-protected control channel and encrypted local storage. Do not copy
them into mailbox headers, public IPFS, shared pubsub, global indexes, logs,
telemetry or error responses. A valid freshness proof does not replace operation
signatures, domain permissions, revocation checks, MLS verification or replay
protection.

## Verification

Unit tests cover native Ed25519 signatures, exact request matching, signer
pinning, tampering, protocol-domain separation, malformed encodings, ambiguous
JSON, bounds and fixed redacted errors. `yarn test:private-freshness`, after
`yarn build`, bundles the public API for Chromium and verifies agreement with
native Node and browser WebCrypto using disposable test keys.
