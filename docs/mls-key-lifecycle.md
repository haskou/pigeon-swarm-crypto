# MLS and private delivery key lifecycle

The `@haskou/pigeon-swarm-crypto/mls` entry point implements the client-side
cryptographic state machine for private messaging. It uses RFC 9420 MLS with
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` and wraps every complete MLS
Application, Commit or Welcome message in a recipient-specific RFC 9180 HPKE
envelope before storage or transport.

## Dependency decision

The selected implementation is `ts-mls` 1.6.4, pinned exactly together with
`@noble/ciphers` 2.1.1 and `@noble/curves` 2.0.1. The package is sourced from
the npm registry and its upstream repository is
[`LukaJCB/ts-mls`](https://github.com/LukaJCB/ts-mls). These dependencies are
MIT licensed and run in Node.js 20.20.2 or newer and bundled Chromium. The
integration uses only the standard 0x0001 ciphersuite.

`ts-mls` has not undergone a formal security audit. Pin upgrades, inspect their
source and changelog, rerun the MLS Working Group vectors and both runtime
suites, and obtain security-focused review before release. A passing test suite
does not replace independent cryptographic review.

## Independent keys and trust

Each device owns a persistent Ed25519 signing credential. Every one-use join
package generates independent X25519 init and leaf keys. Each daily private
delivery descriptor has another independently generated X25519 HPKE key pair
and a random 256-bit mailbox ID. Encryption keys are never converted from the
signing key.

Every MLS session requires an `MlsCredentialVerifier`. The application must
bind the credential identity and signing public key to the current authorized
device set. There is no permissive verifier. A device signs its complete daily
descriptor schedule with `authenticateDeliverySchedule`; receivers use
`AuthenticatedPrivateDeliverySchedule.verify` against the already trusted MLS
credential and authorization revision before accepting it.

Keep credential identities opaque and random. A username, account ID, group ID,
conversation ID or relationship ID in a credential or mailbox descriptor would
reintroduce linkable metadata even though message content remains encrypted.

## MLS transitions and persistence

`MlsGroupSession` is immutable. Encryption, decryption, refresh and membership
changes return a replacement session. The application authenticates the signed
control transition first, applies its Commit, compares the resulting
`contextHash` and epoch with the control record, then atomically persists the
replacement protected session and trusted control checkpoint before
acknowledging it.

`refresh()` advances the epoch without changing membership. Removing a device
advances the epoch and prevents a holder of that device's previous state from
reading later messages, even when it receives the public transitions. Offline
members apply missed authenticated commits in order. A group transition accepts
at most 128 devices.

`protectState` is the only public MLS state export. Device signing identities,
one-use join packages and private delivery schedules also have root-protected
forms. Each uses a separate HKDF domain and fresh salt and nonce with
AES-256-GCM. `restore` requires an application-trusted epoch; mismatches in
either interrupted-write order fail instead of silently restoring old state.
Delete superseded local snapshots after atomic adoption.

Root keys, second factors, live device identities, join packages, MLS sessions
and delivery schedules keep secrets in native private fields. Generic JSON
serialization and ordinary object inspection do not expose them. Exporting a
root key or second factor requires an explicit `valueOf()` call. Delivery
schedule restore additionally requires the previously trusted descriptor
commitment, so a valid older protected schedule cannot silently replace it.

## Recipient-specific private delivery

`PrivateDeliveryKeySchedule.generate` creates the current UTC day plus seven
future daily descriptors. Each descriptor binds its independent mailbox and
HPKE public key, write interval, maximum ciphertext expiry and authorization
revision. When this authenticated window is exhausted, keep outgoing data local
until an authorized replacement schedule arrives.

`PrivateDeliveryEnvelope` uses HPKE base mode with
DHKEM(X25519, HKDF-SHA-256), HKDF-SHA-256 and AES-128-GCM. Every recipient copy
uses a fresh context and encapsulated key. The exact JCS AAD contains only
`version`, `mailboxId`, `deliveryId`, `expiresAt` and `bucketBytes`. The four
wire buckets are 4,096, 16,384, 65,536 and 262,144 bytes. The encrypted plaintext
contains a four-byte frame length, the canonical protected frame and zero
padding. Header substitution, noncanonical identifiers, padding changes,
recipient mismatch and content tampering fail with the same public error.

Retain an old delivery private key until its write-validity end plus the maximum
accepted retention. This permits a last-moment valid write to remain decryptable
until its declared expiry. `retire` destroys keys after that boundary. `revoke`
destroys every specified unused descriptor immediately; distribute a newly
authenticated schedule for the remaining relationships.

## Limits

The mailbox service can still observe random mailbox and delivery identifiers,
bucket size, coarse expiry, queue volume and timing. Recipient-specific HPKE
hides MLS group IDs, frame kinds and participant data from that service, but it
does not provide traffic-flow anonymity. Network peers can still observe network
activity unless a separate anonymity layer is used.

A compromised unlocked device can read plaintext and current secrets available
to that device, impersonate it until revocation is adopted, and retain anything
it already decrypted. MLS rotation limits future access after recovery or
removal; it cannot erase copied plaintext, replicated ciphertext, backups or old
IPFS blocks. Retained history keys weaken forward-secrecy claims for that saved
history. The suite is not post-quantum secure.

This entry point is a new versioned protocol boundary. It deliberately has no
fallback to the legacy shared network key or old asymmetric envelope. Existing
published data is outside this migration and may remain readable under its old
keys indefinitely.

## Verification

The Node lifecycle suite covers admission, real application encryption, refresh,
device removal, retained stolen state, offline catch-up, replay, out-of-order
commits and both interrupted-write rollback orders. The private-delivery suite
covers the shared byte vector, independent recipient copies, authenticated daily
schedules, tampering, wrong recipients, expiry, revocation, last-minute delivery
and root-protected restore. Chromium executes the same bundled public API and
opens a delivery encrypted by Node. Pinned MLS Working Group fixtures verify
RFC 9420 message decoding and byte-for-byte re-encoding.
