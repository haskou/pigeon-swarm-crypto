# Bearer capabilities

`BearerCapability` creates and checks the bearer secrets Pigeon Swarm uses for
mailbox access, private blob access, call scopes, realtime tickets and node
registration codes. A holder proves authority by presenting the token; the
server stores only its commitment.

## Interface

```ts
const { token, hash } = BearerCapability.generate();

const commitment = BearerCapability.hash(presentedToken);

const allowed = BearerCapability.verify(presentedToken, storedCommitment);
```

## Format

- Token: 32 bytes from the platform CSPRNG, unpadded base64url, 43 characters.
- Accepted tokens match `^[A-Za-z0-9_-]{20,128}$`, the same bound the node's
  `Authorization: Bearer` route accepts. Shorter, longer, padded, standard
  base64, whitespace-wrapped or non-ASCII tokens are rejected.
- Commitment: lowercase hex SHA-256 of the UTF-8 token text, 64 characters.

## Validation

`hash` throws `InvalidBearerCapabilityError` for any malformed token. The error
has a fixed message and never contains the token.

`verify` accepts untrusted input of any type and returns `false` for a
malformed token or a commitment that is not exactly 64 lowercase hex characters.
It then compares the recomputed digest with the stored commitment over all 32
bytes without an early exit, so the response time does not reveal how many
leading bytes matched.

## Application responsibilities

Tokens are bearer secrets. Applications must transmit them only over
authenticated, encrypted channels, never log them, and persist only the
commitment. Revocation means deleting or replacing the stored commitment.
Deriving a token from other data is not supported: always use `generate`.

## Vectors

`@haskou/pigeon-swarm-crypto/vectors/bearer-capabilities.json` lists valid
tokens with their commitments, malformed tokens that `hash` must reject, and
`verify` cases with the expected boolean. Node and browser consumers run the
same file.
