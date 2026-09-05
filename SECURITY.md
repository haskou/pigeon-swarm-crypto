# Security Policy

`@haskou/pigeon-swarm-crypto` contains security-sensitive code.

Do not disclose suspected vulnerabilities in public issues. Report them privately through GitHub's private vulnerability reporting when enabled, or contact the repository owner directly.

Cryptographic compatibility changes must preserve the ability to read existing Pigeon Swarm data unless a migration explicitly replaces the old format. New cryptographic constructions require test vectors and security-focused review before release.

## Security boundaries

The library provides cryptographic operations, not a complete secure messaging
protocol. Applications remain responsible for authenticating public keys, storing
secrets, enforcing authorization and password policy, preventing replay, rotating
keys and validating complete attachment sequences.

Ephemeral sender keys in asymmetric encryption do not establish forward secrecy
against later compromise of the recipient's long-lived private key. Shared
symmetric keys do not isolate participants from one another. No anonymity or
protection of traffic patterns, recipient relationships or timing is provided.

IPFS publication can leave ciphertext and metadata available indefinitely.
Deleting a local copy, changing a database or rotating a key does not erase copies
already held by other peers. Consider future key compromise when deciding which
data to publish.

Never log passwords, private or symmetric keys, decrypted content, or complete
cryptographic input errors. Reproduce reports with synthetic data. Documentation
and automated coverage do not constitute an independent cryptographic audit.
