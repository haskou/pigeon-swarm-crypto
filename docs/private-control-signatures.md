# Private control signatures

`PrivateControlSignature` verifies the v1 authorization binding carried by an MLS
Commit or Welcome. Candidate administrators cannot authorize their own admission:
verification uses the previously accepted policy, including its quorum and exact
sequencer. This implements the signature boundary in the
[private protocol contract](https://github.com/haskou/pigeon-swarm/blob/main/docs/privacy/CONTRACTS.md#protected-operation-boundary).
It does not change legacy OrbitDB acceptance or implement MLS.

## Trusted checkpoint

Pass `trustedCheckpointJson` from the client's or node's own previously verified
state. Its exact fields are `scopeId`, `revision`, `headHash`, `mlsEpoch` and
`policy`. The policy contains the complete v1 authorization policy. The initial
checkpoint must come from pinned genesis verification; later checkpoints come
from verified transitions and matching MLS state persisted atomically.

This is a local API input, not another network credential. Never accept a
checkpoint or previous policy supplied by the sender of the candidate operation.
Structural validation cannot establish where a caller obtained its trust anchor.
The library cannot authenticate a checkpoint merely from these five fields.

## Two-stage processing

```ts
import { PrivateControlSignature } from '@haskou/pigeon-swarm-crypto';

const authenticatedBinding = PrivateControlSignature.authenticate(
  receivedAuthorizationJson,
  trustedCheckpointJson,
  actualMlsMessageHash,
);

const verifiedBinding = PrivateControlSignature.verify(
  authenticatedBinding,
  trustedCheckpointJson,
  actualMlsMessageHash,
  resultingMlsContextHash,
);
```

`authenticate` checks the binding before the MLS adapter processes the supplied
message. Calculate `actualMlsMessageHash` as SHA-256 of the exact decoded control
message bytes, encoded as canonical unpadded base64url. Validate the enclosing
frame's version, kind, encoding and size separately. Do not substitute a hash
copied from the received binding.

After authentication, process MLS on a temporary state copy. Calculate
`resultingMlsContextHash` from the complete final GroupContext TLS encoding, then
call `verify`, which repeats authentication and checks that context. The MLS
adapter must also compare the full resulting device/credential set with
`policy.devices`; this package has no MLS tree to perform that comparison.

Only then may the application adopt the candidate. Persist the policy, head,
deduplication marker and MLS state atomically, with a compare-and-swap against the
same checkpoint. If another transition has advanced the scope, re-evaluate rather
than overwriting it. A successful `authenticate` alone is not adoption permission.

## Enforced rules

- Exact binding fields, no duplicate JSON keys, canonical 32-byte hash/key and
  64-byte signature encodings, existing strict JSON size/depth/token limits.
- Exact scope and parent head; revision and epoch advance by one using safe
  integers. Missing intermediate transitions must be recovered first.
- Recomputed JCS/SHA-256 policy and head hashes. The entire unsigned binding is
  signed under `pigeon.private-control.v1` followed by a zero byte.
- One to 128 distinct devices and credential hashes. Administrators are distinct
  admitted devices, the sequencer is an administrator, the freshness authority
  is admitted, and the threshold is satisfiable.
- Enough distinct valid signatures from the previous administrators, including
  the previous sequencer. Unknown signers and invalid extra signatures are
  rejected even if other signatures form a quorum.
- The lease revocation signing and HPKE keys remain unchanged. Replacing them
  requires explicit scope migration, not an ordinary transition.
- Errors use `InvalidPrivateControlError` without submitted data or a cause.

The checkpoint's lease revocation key may belong to an original owner no longer
in the current device roster. It is an immutable lease-retirement authority, not
an implicit current administrator.

## Remaining application guarantees

This verifier is stateless. Persist the most recent checkpoint, reject rollback
and replay after restart, quarantine conflicting children and keep out-of-order
operations pending. A malicious sequencer can sign conflicting children; the
verifier cannot discover a second child it has never seen.

Before issuing any control signature, the sequencer must durably reserve one
child per parent and resume that reservation after restart. This API issues no
signatures and provides no leader election or recovery bypass. Freshness proofs,
device revocation and operation-specific domain permissions remain required.
Keep bindings inside participant-encrypted scopes: signatures do not hide
membership, device keys or the social graph.

## Validation

Tests use native Node Ed25519 signatures and independent SHA-256 calculations,
including malicious policies with recomputed hashes, administrator replacement,
missing sequencers, invalid checkpoints and a 128-device quorum.
`yarn test:private-control` bundles the package for Chromium and checks acceptance
and rejection against native WebCrypto. These are control-signature tests with
synthetic context/message hashes, not a working MLS group or a complete private
messaging deployment.
