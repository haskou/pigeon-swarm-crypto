# Wire formats

## Package boundaries

Import keys, signatures, encrypted envelopes and digest-computation factories from
`@haskou/pigeon-swarm-crypto`. Keep generic types such as `Media`, `Password`,
`StringValueObject`, `Timestamp` and identifiers in `@haskou/value-objects`.
Install version 8.3.3 or a later 8.x release as a direct dependency of the application. The crypto package
declares it as a peer dependency (`^8.3.3`) so compatible 8.x updates share the consumer's
runtime classes.
Multiple incompatible copies can break class identity and `instanceof Media`.

`hasValue` deliberately ignores the concrete type. Do not replace every equality
check mechanically: identity and authorization decisions usually require the
domain type to match.

## Formats

All envelope components below are joined by a period. Binary components use
standard Base64 unless stated otherwise.

| Data | Format | Notes |
| --- | --- | --- |
| Private key | Ed25519 PKCS#8 PEM | Key material and encoding; `PrivateKey.fromSeed` imports a 32-byte seed |
| Public key | Ed25519 SPKI PEM | Key material and encoding; `PublicKey.fromRaw` and `toRaw` convert strict 32-byte keys |
| Signature | Base64 Ed25519 signature | Signatures cover supplied bytes; applications own canonicalization. Every Ed25519 verification in the package (`PublicKey`, the private signature formats, relay records and the MLS ciphersuite) goes through one internal verifier that uses RFC 8032 strict decoding with canonical `A` and `R` encodings, plus rejection of small-order public keys; ZIP-215 is not accepted. A malformed PEM or key, a non-canonical `S`, or a small-order key makes verification return `false` rather than throw. The adapter imports exactly `{ ed25519, x25519 }` from `@noble/curves/ed25519.js`, holds the only `ed25519.verify` call (always with `{ zip215: false }`), and otherwise uses only `getPublicKey`, `sign`, `Point.fromBytes`, `utils.randomSecretKey`, `utils.toMontgomery` and `utils.toMontgomerySecret`. An import guard test fails if any `src` module other than the internal adapter names the `@noble/curves` ed25519 binding in a string, imports or re-exports anything from it other than `x25519`, imports or requires `node:vm` or `module`, names `require`, `createRequire`, `eval`, `Function`, `_load`, `getBuiltinModule` or a vm run method in an import, export, identifier or string (except a direct call to `require` with a string-literal specifier), reads `.constructor`, applies a computed key to `globalThis`, `global`, `process`, `module`, `require` or `Module`, or calls `import()` with a non-literal specifier. It is a static text scan, so it does not prove the absence of computed access through values it cannot resolve |
| Symmetric payload | `v1.aes-256-gcm.iv.ciphertext.tag` | Authenticates the default header AAD unless custom AAD is supplied |
| Asymmetric payload | `v2.x25519-hkdf-sha256-aes-256-gcm.ephemeralPublicKey.iv.ciphertext.tag` | Only this envelope is accepted |
| Protected private key | `v3.scrypt.N16384.r8.p5.salt.iv.tag.ciphertext` | Only this envelope is accepted |
| Private control transition | `pigeon.private-control.v2` signed canonical JSON | Derives the binding from the authenticated operation and requires its claimed resulting head to equal the signed checkpoint head without creating a circular hash |
| Proof of work | SHA-256 over length-prefixed `pigeon-identity-admission:v2` or `pigeon-mailbox-creation:v2` preimages | Canonical decimal nonce; see [Proof of work](proof-of-work.md) |
| Private network keys | HKDF-SHA256 of the network seed with `pigeon.private-network.*.v2` labels | See [private-network-keys.md](private-network-keys.md) |
| Private network envelope | `{"ciphertext","nonce","version":2}` AES-256-GCM JSON | Pubsub envelopes bind network id and topic |
| TURN credential | `expiresAt:user` and Base64 HMAC-SHA1 | Fixed by coturn; see [turn-credentials.md](turn-credentials.md) |
| Relay record signature | Ed25519 over sorted-field JSON | See [relay-records.md](relay-records.md) |

The asymmetric HKDF context is `@haskou/value-objects/asymmetric-payload/v2`. It is
part of the protocol and independent of the package name.

Symmetric encryption limits a plaintext to 8 MiB; asymmetric encryption limits it
to 1 MiB. Symmetric nonces contain 12 bytes and GCM tags contain 16 bytes. Larger
attachments need the application's chunked format and its own completeness checks.

## Error handling

Treat authentication failure as a failed operation, not as permission to return
unverified plaintext or accept an alternative key. Distinguish malformed input,
unsupported formats and failed authentication at the application boundary without
logging payloads or key material. Errors may include supplied invalid values;
applications must redact them before logging or sending diagnostics.

## Changing a format

Introduce a new version for changes to algorithms, derivation parameters,
authenticated data, key encoding or component order, and replace the previous
version rather than accepting both. Include known-answer fixtures and verify both
intended interoperability and tampering rejection. A same-version round trip alone
cannot establish correctness.
