# Private operation signatures, version 1

This is the shared signature boundary for the private-operation contract in
[Pigeon Swarm ADR-001](https://github.com/haskou/pigeon-swarm/blob/main/docs/privacy/CONTRACTS.md).
It does not activate the private protocol or replace application authorization.
Existing ciphertext, PEM, password derivation and signature APIs are unchanged.

## Interface

`PrivateOperationSignature.sign(unsignedJson, privateKey)` accepts a JSON string
with the eight unsigned envelope fields and returns the complete canonical signed
JSON. The `authorDeviceKey` must be the raw Ed25519 public key corresponding to
that private key, encoded as canonical unpadded base64url.

`PrivateOperationSignature.verify(signedJson, expectedAuthorDeviceKey)` verifies
the complete envelope and returns canonical signed JSON. The expected device key
must come from an independently authenticated scope policy or verified device
binding. Never obtain the expected key solely from the same untrusted envelope.
A valid signature establishes authorship by that key, not membership or permission.

All failures throw `InvalidPrivateOperationError` with a fixed message. It contains
no input, key, nested parser exception or underlying cause. Callers must likewise
avoid logging the submitted JSON or including it in telemetry.

The application must still verify scope, device-to-identity binding, current
signed authorization head, revision, revocation, causal dependencies, duplicate
operation IDs and kind-specific payload permissions before applying any state.
This API does not validate payload business rules, MLS state, freshness proofs,
control transitions, or Commit/Welcome frames. In particular, signing a
`membership.commit` operation does not authorize a membership change. Those checks
remain work in crypto #5 and node #288; neither issue is closed by this addition.

## Signed bytes and strict input handling

The signed bytes are UTF-8 `pigeon.private-operation.v1`, a zero byte, and the
[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html) encoding of the envelope
without `signature`. All other fields, including payload and causal links, are
covered. Ed25519 verification uses strict mode (`zip215: false`). Changing the
domain separator, scope, author, revision, operation ID, kind, dependencies or
payload invalidates the signature.

The canonicalizer is `canonicalize` 2.1, Apache-2.0, from
[the JCS reference implementation](https://github.com/erdtman/canonicalize).
Version 2 is used because the package has a synchronous CommonJS public API;
versions 3 and 4 expose an import-only entrypoint. Input is restricted to parsed
JSON, so programmatic objects, functions, accessors and custom serializers never
enter canonicalization. Lone Unicode surrogates are rejected explicitly; Unicode
is not normalized. Non-finite numbers are rejected by the canonicalizer.

[Microsoft jsonc-parser](https://github.com/microsoft/node-jsonc-parser), MIT,
preserves object properties in its syntax tree. Comments and trailing commas are
disabled. Duplicate decoded property names are rejected at every nesting level,
including escaped spellings, before `JSON.parse` can collapse them. This parser
is a validation layer; it does not make JSON-with-comments an accepted format.
The package browser mapping selects its ESM build, avoiding dynamic UMD requires
in browser bundles; Node continues to use its CommonJS build.

Before building a syntax tree, a scanner bounds input to 256 KiB of UTF-8, 32
container levels and 8,192 tokens. The signed output must fit the same limits.
Identifiers and signatures are checked by decoding and re-encoding exact byte
lengths; padding, alternate alphabets and nonzero unused bits are rejected.
Envelope fields and version/kind are closed, revisions are nonnegative safe
integers, and causal links are unique with at most 32 entries. The surrounding
MLS/HPKE adapter must additionally enforce its own, potentially tighter, wire
budget before committing cryptographic state.

## Privacy and verification limits

The signed JSON contains sensitive scope, author and payload information. It must
remain inside participant encryption and encrypted local storage. Do not place it
in public IPFS, shared pubsub, mailbox headers, transport logs or global indexes.
Signatures alone do not conceal metadata, prevent replay or enforce revocation.
This change neither erases existing replicated copies nor changes legacy traffic.

Unit tests cover malformed and ambiguous inputs, altered fields, wrong pinned
keys, protocol-domain confusion, weak Ed25519 keys, bounds and fixed errors.
`yarn test:private-signatures`, after `yarn build`, bundles the public package for
real Chromium and exchanges signatures with Node and native WebCrypto using only
disposable test keys. CI runs the same interoperability check. These checks are
not an independent security audit or an MLS interoperability claim.
