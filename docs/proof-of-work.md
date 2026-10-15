# Proof of work

`ProofOfWork` mints and verifies the hashcash-style proofs that Pigeon Swarm
requires before admitting an identity to its networks and before creating an
opaque mailbox. It owns the preimage encoding, the leading-zero-bit check and the
nonce search; callers only choose the difficulty.

## Interface

```ts
const admission = ProofOfWork.identityAdmission(identityId, networkIds);
const nonce = await admission.mint(difficultyBits);
admission.verify(receivedNonce, difficultyBits);

const creation = ProofOfWork.mailboxCreation(
  mailboxId,
  postTokenHash,
  readTokenHash,
);
const workerNonce = creation.mintSync(difficultyBits);
```

`mint` yields to the event loop every 4096 attempts so a browser main thread
stays responsive. `mintSync` never yields; use it in workers, servers and
fixtures. `mintSync` also takes an optional `accepts(nonce)` predicate and
returns the first nonce that meets the difficulty and that the predicate
accepts, which lets tests build proofs with an exact amount of work without
hashing on their own. Both search decimal counters from `0`, so a challenge and
difficulty always mint the same nonce.

## Format

```text
lp(x)    = uint32be(byte length of x) || ASCII bytes of x
preimage = lp(domain) || fields || lp(nonce)
valid    = SHA-256(preimage) starts with at least difficultyBits zero bits
```

| Proof              | Domain                         | Fields                                                                       |
| ------------------ | ------------------------------ | ---------------------------------------------------------------------------- |
| Identity admission | `pigeon-identity-admission:v2` | `lp(identityId) \|\| uint32be(network count) \|\| lp(networkId)` per network |
| Mailbox creation   | `pigeon-mailbox-creation:v2`   | `lp(mailboxId) \|\| lp(postTokenHash) \|\| lp(readTokenHash)`                |

Network ids are encoded in ascending byte order, so the proof covers the set of
networks rather than the order the caller listed them in.

Version 1 joined the same values with `:`. A field that contained `:` could then
move part of its value into the neighbouring field without changing the hash, so
one proof covered several different challenges. Length prefixes make every
field boundary explicit. Version 2 replaces version 1 outright: there is no
version 1 reader.

## Limits and validation

| Input            | Rule                                                              |
| ---------------- | ----------------------------------------------------------------- |
| Challenge fields | 1 to 256 visible ASCII characters (`0x21`-`0x7e`)                 |
| Network ids      | 1 to 64 distinct ids per identity admission                       |
| Nonce            | Canonical decimal string: `0` or 1 to 16 digits without leading 0 |
| `difficultyBits` | Integer from 1 to 32                                              |

The factories and every method throw `InvalidProofOfWorkError` for a malformed
challenge or difficulty. Both come from the caller: challenge fields from
already validated identities or mailboxes, and the difficulty from the node's
pricing policy. `verify` returns `false` for any nonce that is not a canonical
decimal string, without hashing it, and otherwise hashes exactly one bounded
preimage. The challenge prefix is hashed once when the factory runs; each
verification and each mining attempt reuses that SHA-256 state and hashes only
the nonce block. The leading-zero count walks all 32 digest bytes, so
verification costs the same amount of work for any nonce and difficulty. The
error message is fixed, never echoes input and carries no cause.

## Application responsibilities

The library does not price work. The caller picks `difficultyBits` from its own
policy (the node currently charges 16 to 20 bits) and must bind the challenge to
the values it later trusts: the published identity and its networks, or the
mailbox id and token hashes it stores. A proof does not expire and is not
single-use; replay protection belongs to the record it admits.

## Vectors

`vectors/proof-of-work.json` is shipped in the package and exported as
`@haskou/pigeon-swarm-crypto/vectors/proof-of-work.json`. It holds the accepted
proofs with their preimages, digests and minted nonces, the rejected proofs
(insufficient work, replay for another challenge, the former `:` delimiter moved
across a field boundary and malformed nonces such as an oversized one) and the
challenges and difficulties that must be refused.
`yarn test:proof-of-work` checks that Node and Chromium agree on all of them.
