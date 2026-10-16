# Safety numbers and key fingerprints

## Safety number

`SafetyNumber.between(first, second)` lets two contacts compare identities out
of band. The ids are ordered, so both sides compute the same value. The digest
is SHA-512 of `pigeon-swarm:safety-number:v1`, the lower id and the higher id
joined by `\n`. The first 60 bytes form 12 groups of 5 bytes; each group is read
big-endian, reduced modulo 100000 and zero-padded to five digits. The result is
a frozen array of 12 strings. Identity ids are non-empty, contain no newline
and are at most 4096 UTF-8 bytes.

## Key fingerprint

`KeyFingerprint` formats the first 16 bytes of a SHA-256 digest as uppercase
hex in groups of four, for example `FD11 0D30 1D2F 077D E141 4B8F 99F4 41B1`.

- `ofPublicKey(publicKey)` hashes the SPKI DER of a `PublicKey`.
- `ofPublicBytes(bytes)` hashes raw public bytes.
- `ofSecret(secret)` hashes `pigeon-swarm:key-fingerprint:v1\n || secret`, so a
  secret fingerprint never equals a hash that a protocol derives from the same
  secret.

Inputs are at most 65536 bytes. `vectors/safety-number.json` and
`vectors/key-fingerprint.json` pin the outputs.
