# Wire formats and migration

## Moving from value-objects

Import keys, signatures, encrypted envelopes and digest-computation factories from
`@haskou/pigeon-swarm-crypto`. Keep generic types such as `Media`, `Password`,
`StringValueObject`, `Timestamp` and identifiers in `@haskou/value-objects`.
Install version 7 as a direct dependency of the application. The crypto package
declares it as a peer dependency so compatible 7.x updates share the consumer's
runtime classes.
Multiple incompatible copies can break class identity and `instanceof Media`.

This migration changes package ownership, not serialized data. Do not rewrite
stored keys, ciphertext or signatures merely to update an import. The
interoperability suite checks signatures, symmetric and asymmetric encryption, and
protected private keys in both directions against `value-objects` 2.10.0 and 3.0.1.
Those older versions are test-only dependencies, never runtime dependencies.

`ValueObject.isEqual` now requires matching concrete types as well as values.
`hasValue` deliberately ignores the concrete type. Do not replace every equality
check mechanically: identity and authorization decisions usually require the
domain type to match.

## Current writers and supported readers

All envelope components below are joined by a period. Binary components use
standard Base64 unless stated otherwise.

| Data | Current output | Compatibility |
| --- | --- | --- |
| Private key | Ed25519 PKCS#8 PEM | Preserved key material and encoding |
| Public key | Ed25519 SPKI PEM | Preserved key material and encoding |
| Signature | Base64 Ed25519 signature | Signatures cover supplied bytes; applications own canonicalization |
| Symmetric payload | `v1.aes-256-gcm.iv.ciphertext.tag` | Reader also supports existing envelopes without the default header AAD when no custom AAD is supplied |
| Asymmetric payload | `v2.x25519-hkdf-sha256-aes-256-gcm.ephemeralPublicKey.iv.ciphertext.tag` | Reader also accepts the earlier four-component asymmetric envelope |
| Protected private key | `v3.scrypt.N16384.r8.p5.salt.iv.tag.ciphertext` | Reader also accepts supported v2 and legacy PBKDF2 envelopes |

The asymmetric HKDF context remains
`@haskou/value-objects/asymmetric-payload/v2`. That string is part of the existing
protocol: changing it to the new package name would prevent decryption.

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

Keep existing read support until a documented migration explicitly retires it.
Introduce a new version for changes to algorithms, derivation parameters,
authenticated data, key encoding or component order. Include fixtures produced by
the former implementation and verify both intended interoperability and tampering
rejection. A same-version round trip alone cannot establish compatibility.
