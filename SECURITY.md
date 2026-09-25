# Security Policy

`@haskou/pigeon-swarm-crypto` contains security-sensitive code.

Do not disclose suspected vulnerabilities in public issues. Report them privately through GitHub's private vulnerability reporting when enabled, or contact the repository owner directly.

Cryptographic compatibility changes require an explicit versioned migration or
an explicitly documented breaking boundary. New cryptographic constructions
require test vectors and security-focused review before release.

## Security boundaries

The library provides cryptographic operations, not a complete secure messaging
protocol. Applications remain responsible for authenticating public keys, storing
secrets, enforcing authorization and password policy, preventing replay, rotating
keys and validating complete attachment sequences.

Ephemeral sender keys in asymmetric encryption do not establish forward secrecy
against later compromise of the recipient's long-lived private key. Shared
symmetric keys do not isolate participants from one another. No anonymity or
protection of traffic patterns, recipient relationships or timing is provided.

The MLS entry point provides forward secrecy within message generations and
epoch-based post-compromise recovery when valid commits are applied and obsolete
state is deleted. It does not authenticate devices by itself: callers must supply
a verifier bound to their authorization state. It also cannot prevent rollback
when an attacker can replace the protected session snapshot and its application
checkpoint with an older valid pair.

IPFS publication can leave ciphertext and metadata available indefinitely.
Deleting a local copy, changing a database or rotating a key does not erase copies
already held by other peers. Consider future key compromise when deciding which
data to publish.

Recipient-specific private delivery hides MLS framing and participant data from
the mailbox service. The service still observes random mailbox and delivery IDs,
bucket size, coarse expiry, queue volume and timing. Those observations can be
correlated with external network traffic. The library does not provide anonymity.

Never log passwords, private or symmetric keys, decrypted content, or complete
cryptographic input errors. Reproduce reports with synthetic data. Documentation
and automated coverage do not constitute an independent cryptographic audit.
