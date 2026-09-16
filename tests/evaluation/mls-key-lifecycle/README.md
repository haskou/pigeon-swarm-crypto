# MLS key lifecycle evaluation

This executable evaluation tests `ts-mls` **1.6.4** against the lifecycle required
by crypto #5. It is not a production adapter, does not change Pigeon encryption,
and does not select this dependency for production. Its isolated private package
and lockfile are not part of the published library or its runtime dependencies.

## Run

Use Node 24.18.0 and run from this directory:

```sh
npm ci --ignore-scripts
npx --no-install playwright install chromium
npm test
```

The same scenario runs independently in Node and actual Chromium with fresh
random keys, real MLS wire encoding and the selected standard suite 0x0001.
A loopback-only HTTP server serves an empty test page and is closed afterward.
All participants and key material are synthetic; no application network is used.

## Assertions

- Three separately generated devices exchange a message before removal.
- Reusing a signing credential while generating a second key package creates
  different HPKE leaf and initialization keys. Encryption-key generation is not
  a deterministic conversion of that signing credential.
- A pinned credential/key map rejects an unregistered participant. The permissive
  default authentication service is replaced; this map is a fixture trust anchor,
  not an implementation of Pigeon's distributed authorization policy.
- A Remove commit advances the epoch. The removed device retains a serialized
  copy of its prior secret state and cannot decrypt new application messages.
- The excluded device also receives the actual removal commit. Ignoring its
  removed status and installing the new public tree/context does not restore
  decryption; the test does not obtain exclusion simply by withholding the commit.
- Replacing its old public group context with the current public context does
  not restore decryption, so rejection is not tested only against an old epoch
  number.
- A remaining offline device reconstructs its state, applies the missing commit,
  reconstructs again and decrypts the next message.
- Modified ciphertext, repeated application delivery and replayed commits fail.
- Another commit rotates the epoch without changing membership. Remaining
  participants still exchange content; the removed device still cannot read it.

Successful comparison checks plaintext and protocol behavior, not merely epoch
counters. Consumed secrets are zeroed for honest participants; the deliberately
retained attacker snapshot is not erased to obtain the desired result.

## Evaluation limits and dependency decision

The [upstream project](https://github.com/LukaJCB/ts-mls) explicitly states that it
has not undergone a formal security audit. Version 1.6.4 is MIT licensed; its
required HPKE dependency is pinned to `@hpke/core` 1.9.0. This fixture also pins
`@noble/curves` 2.0.1. The published package API differs from current upstream
main-branch examples; tests must use the locked version's actual interface.

These checks demonstrate lifecycle behavior in two runtimes of the same
implementation. They are not independent MLS implementation interoperability,
RFC vector certification, proof of secure memory erasure, an audited threat model
or evidence that Pigeon currently provides revocation. The test does not persist
secrets to disk or model an atomic authorization/MLS transaction interrupted by
a process crash. Serialization/reconstruction is not rollback protection.

[OpenMLS](https://book.openmls.tech/) is another candidate, maintained by Phoenix
R&D and CE Labs. Its [Wasm support](https://book.openmls.tech/user_manual/wasm.html)
requires JavaScript randomness/time support and a maintained JS/Wasm boundary in
this TypeScript package. Its API explicitly separates signature keys from HPKE
keys and [supports encryption-key updates](https://book.openmls.tech/user_manual/updates.html).
No OpenMLS integration or cross-implementation comparison has been performed here.
Do not infer that either candidate is audited for our intended configuration.

Before production selection, compare release provenance, maintenance, relevant
security reviews, runtime support and independent vectors/interoperability. Then
integrate existing genesis/control verifiers with complete credential-set checks,
atomic persisted state, device revocation, stale-state rejection, recipient HPKE
descriptors and the documented migration. Crypto #5 remains open.
