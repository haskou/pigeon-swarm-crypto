# Recovery kit

A recovery key restores an identity when no device remains. It is 32 random
bytes shown to the user once as `psrk1.` followed by unpadded base64url.

`RecoveryKey.fromString` accepts only that exact canonical form. It does not
trim: user interfaces must trim pasted input before parsing. `generate()` uses
the platform CSPRNG. The key keeps its value in a native private field, refuses
JSON serialisation and returns a fresh byte copy from `getBytes()`. `isEqual()`
compares the decoded bytes of both keys in constant time and wipes both copies.

`RecoveryKit.derive(recoveryKey)` returns frozen material. Every key is
HKDF-SHA-256 of 32 bytes over the recovery bytes:

| Material | Salt | Info |
| --- | --- | --- |
| `identityKeyPair` (Ed25519 seed) | `pigeon-swarm:recovery-kit:v1` | `pigeon-swarm:recovery-identity-signing:v1` |
| `rootKey` (`UserRootKey`) | `pigeon-swarm:recovery-kit:v1` | `pigeon-swarm:recovery-user-root:v1` |
| `recoveryAuthorityKeyPair` (Ed25519 seed) | `SHA-256(identityId)` | `pigeon-swarm:recovery-authority:v1` |

`identityId` is the base64 DER of the identity public key without PEM armour.
Intermediate seeds and recovery bytes are overwritten after use where the
runtime permits.

`vectors/recovery-kit.json` pins the derived PEM key pairs and root keys.
