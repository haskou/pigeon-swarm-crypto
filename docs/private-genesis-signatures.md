# Private scope genesis signatures

`PrivateGenesisSignature` authenticates the initial authorization record of a
new private scope. It implements the version 1 genesis contract from
[Pigeon Swarm's private-data architecture](https://github.com/haskou/pigeon-swarm/blob/main/docs/privacy/CONTRACTS.md#protected-operation-boundary).
It is a cryptographic prerequisite, not an integrated authorization system or an
MLS implementation. Existing OrbitDB writes are unchanged.

## Trust inputs

```ts
import { PrivateGenesisSignature } from '@haskou/pigeon-swarm-crypto';

const canonicalGenesis = PrivateGenesisSignature.verify(
  receivedJson,
  pinnedOwnerDeviceKey,
  expectedScopeId,
  verifiedMlsContextHash,
);
```

All three expected values are mandatory. Obtain the owner and scope through a
verified invitation/contact channel or local scope creation, never by copying
them from the received record. Compute the context hash from the initial final
MLS GroupContext verified by the caller's MLS adapter. A node-provided owner key
and its self-signature do not establish trust.

Verification returns canonical JSON only after checking the record shape, hashes,
owner binding and strict Ed25519 signature. It does not fetch keys or trust a node
certificate. The same implementation can be bundled in a browser or run in Node.

`PrivateGenesisSignature.sign(unsignedJson, privateKey)` signs a complete unsigned
record whose policy and head hashes have already been calculated. It rejects
inconsistent hashes and a policy belonging to a different key. It neither invents
policy fields nor generates MLS state.

## Version 1 rules

- Revision and MLS epoch are zero; the parent head is null. There is exactly one
  initial device, authority and signature, all belonging to the pinned owner.
- Threshold is one. Sequencer, freshness authority and lease revocation signing
  authority are the same owner. The lease revocation HPKE key is a distinct
  32-byte key. Its ownership and successful HPKE use remain adapter checks.
- Credential and context hashes, scope identifiers, keys and signatures use
  canonical unpadded base64url. The initial MLS adapter must also match the
  credential hash to the owner's actual MLS credential.
- `policyHash` is SHA-256 of the JCS policy. `headHash` is SHA-256 of the JCS object
  containing exactly `scopeId`, `revision`, `parentHeadHash`, `mlsEpoch`,
  `mlsContextHash` and `policyHash`.
- The signed bytes are UTF-8 `pigeon.private-genesis.v1`, a zero byte, then JCS of
  the whole unsigned record. Unknown fields, versions, extra devices or
  authorities, duplicate JSON properties and invalid signatures fail closed.
- Input uses the existing strict JSON limits: 256 KiB, depth 32 and 8,192 tokens.
  Every public failure is `InvalidPrivateGenesisError`, without submitted data or
  an attached cause.

## Application responsibilities

Before exposing a new scope, persist its verified genesis and matching MLS state
atomically. Do not replace an already pinned scope with a different genesis or
use a valid genesis to roll back a later authorization revision. That requires
durable application state; this stateless verifier cannot detect replay by itself.

Subsequent membership transitions, administrator permissions, device revocation,
freshness proofs and operation deduplication are separate checks. A valid genesis
does not authorize every operation by its members. Keep this record inside the
participant-encrypted scope; signing does not hide its keys or metadata.

## Verification

Focused tests sign attacker-controlled records with Node's native Ed25519
implementation, independently calculate SHA-256 hashes and test pinning,
single-owner policy, tampering and cross-protocol replay. `yarn test:private-genesis`
builds the actual package for Chromium and checks agreement with both native Node
crypto and browser WebCrypto. This fixture exercises the genesis signature
boundary, not an MLS group or an end-to-end private conversation.
