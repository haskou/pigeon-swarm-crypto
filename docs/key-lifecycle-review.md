# Key lifecycle review

Review date: 2026-09-16. Baseline: `6d1d99e`.

This is a focused source review and regression report, not an independent
cryptographic audit. It covers the package's current key APIs and the boundary
between its primitives and the planned private messaging protocol.

## What the current package provides

- `SymmetricKey` generates random 256-bit keys and encrypts with AES-GCM and a
  fresh nonce. Callers can bind application context through authenticated data.
- `PrivateKey` signs with Ed25519. `PublicKey.encrypt` uses an ephemeral X25519
  sender key with a static recipient key, HKDF and AES-GCM.
- `EncryptedPrivateKey.create` protects an existing private key using a salted
  scrypt v3 envelope. Re-encrypting that envelope changes password protection;
  it does not replace the underlying identity key or revoke any copies.
- Operation, genesis and control signature verifiers authenticate specific
  protocol bindings. They do not implement MLS, persist group state, distribute
  replacement secrets or apply revocation to existing application stores.

## Confirmed validation-error exposure

`PrivateKey`, `PublicKey` and `SymmetricKey` passed submitted key text to generic
validation errors. Logging a rejected import could therefore retain secret key
material, including a private key mistakenly submitted to a public-key field.

The accompanying fix supplies only lengths or a fixed redacted label, preserving
error classes and all valid key/ciphertext formats. Five regression cases fail
before the change and pass afterward, checking string, JSON and diagnostic
rendering. Existing keys, signatures and encryption compatibility remain covered
by the package's tests.

This is narrowly about rejected key inputs. Explicit key serialization, logging
key objects, malformed ciphertext diagnostics and application logging policies
remain separate surfaces. This change cannot remove previously retained logs.

## Missing lifecycle guarantees

### Signing and encryption currently share a root secret

`CryptoAdapter.privateKeyToX25519` converts the Ed25519 signing seed to an X25519
secret; the public conversion mirrors it. This couples compromise and replacement
of signing and asymmetric decryption keys. The conversion itself is not evidence
of a cryptographic break, but it prevents independent lifecycle management.

New private-protocol devices must generate separate signing, MLS leaf/init and
outer recipient-HPKE keys. Bind the encryption credentials to the signing identity
through authenticated protocol records. Keep symmetric encryption for application
data; key agreement and group updates distribute new symmetric secrets. Rotating
only a password or deriving the next key solely from a compromised old secret does
not establish post-compromise recovery.

The [isolated MLS lifecycle evaluation](https://github.com/haskou/pigeon-swarm-crypto/tree/main/tests/evaluation/mls-key-lifecycle)
exercises independent encryption-key generation, removal, refresh and retained
attacker state in Node and Chromium. It does not activate rotation in Pigeon.

### Generating a key is not rotating a group

There is no group key schedule, epoch state, recipient-specific update protocol,
old-key retirement policy or atomic state adoption in the current public API.
Generating a fresh `SymmetricKey` provides new randomness, but the application
must still authenticate who receives it and prevent excluded devices from
obtaining it. Sending a replacement under a shared key known to a removed member
would not revoke that member.

Implement the already selected MLS integration in
[crypto #5](https://github.com/haskou/pigeon-swarm-crypto/issues/5), with application
integration in [UI #174](https://github.com/haskou/pigeon-swarm-ui/issues/174).
Do not add a custom ratchet or present a key-generation convenience method as
revocation.

### Static recipient encryption does not protect recorded history after theft

The asymmetric envelope contains the ephemeral public key. A holder of the
recipient's long-lived private key can derive the same shared secret and decrypt
recorded envelopes addressed to it. Ephemeral sender keys alone do not establish
forward secrecy against later recipient-key compromise.

MLS epoch evolution and deletion of obsolete protocol secrets must be integrated
and tested. Separately retained plaintext/history backups have their own
compromise boundary; replacing keys cannot make a recipient forget old content.

### Signatures need durable authorization state

The control verifier checks the previous authority policy, but its trusted
checkpoint is supplied by the caller. It cannot detect an application restoring
an older checkpoint after restart or accepting two conflicting transitions.
[node #288](https://github.com/haskou/pigeon-swarm-node/issues/288) must enforce
persisted authorization, replay handling and atomic adoption with MLS state.
Device enrollment and revocation belong to
[node #292](https://github.com/haskou/pigeon-swarm-node/issues/292).

### Compatibility is not a strict new-protocol policy

The symmetric decryptor retains compatibility with legacy ciphertext without
AAD when the caller supplies no AAD. Existing asymmetric and protected-key
readers also accept documented legacy formats. New private-protocol framing must
require its exact version, kind and authenticated context without routing failures
through legacy decryption. Retiring legacy reads requires the migration policy;
silently disabling them would strand stored data.

### Additional input review

PEM constructors currently check text length and shape; the adapter slices the
expected DER prefix length without validating that prefix. Canonical Ed25519
DER validation and independent malformed-key vectors need a separate focused
change. This observation does not establish an authentication bypass.

## Next verifiable delivery

Use the existing [privacy ADR](https://github.com/haskou/pigeon-swarm/blob/main/docs/privacy/ADR-001-private-data.md)
and [protocol contract](https://github.com/haskou/pigeon-swarm/blob/main/docs/privacy/CONTRACTS.md).
The next lifecycle milestone must use a maintained MLS implementation in Node
and an actual browser, with independent standard vectors:

1. Establish a group, admit devices and exchange real encrypted application data.
2. Remove a device, adopt the authorized epoch change and prove that the removed
   device cannot decrypt subsequent messages even with its retained old state.
3. Reject modified, replayed and wrong-scope transitions; recover delayed valid
   transitions without silently rolling back or duplicating operations.
4. Restart between transition preparation and adoption. Recover one coherent
   authorization checkpoint and MLS state, with no partial acceptance.
5. Specify retirement, offline recovery and backup behavior. Test the assumptions
   before making forward-secrecy or post-compromise-recovery claims.

Keep participant identities and MLS framing inside the encrypted delivery scope.
Changing the cipher or storage engine alone does not hide participants, IP
addresses or timing. Mailboxes, metadata minimization and migration remain in
node #289/#291 and pigeon-swarm #32/#33. No changes here rotate production keys,
re-encrypt deployed history or remove data already replicated through IPFS.
