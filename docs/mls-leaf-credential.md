# MLS leaf credential

`MlsLeafCredential` (entry point `@haskou/pigeon-swarm-crypto/mls`) is the
`identity` of the MLS basic credential on every leaf of a Pigeon group. It
binds the leaf's MLS signature public key to one Pigeon identity and to one of
that identity's devices. To present a leaf as another identity's, an attacker
needs that identity's key. A revoked device that still holds the identity key
cannot present a leaf as a current device's without that device's key.

## Format

The credential identity is the UTF-8 encoding of four parts joined by NUL
(`U+0000`):

```text
identityId NUL deviceCredential NUL identitySignature NUL deviceSignature
```

| Part                | Value                                                                                                         |
| ------------------- | ------------------------------------------------------------------------------------------------------------- |
| `identityId`        | Base64 body of the identity's Ed25519 SPKI public key: 59 base64 characters followed by `=`.                   |
| `deviceCredential`  | The device's Ed25519 SPKI public key as a full PEM, `-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----\n`. |
| `identitySignature` | The identity key's Ed25519 `Signature` over the message.                                                      |
| `deviceSignature`   | The device key's Ed25519 `Signature` over the message.                                                        |

Both keys sign the same message:

```text
"pigeon:mls-leaf-credential:v2\n" || RFC 8785 JSON {
  "deviceCredential": deviceCredential,
  "identityId": identityId,
  "signaturePublicKey": unpadded base64url of the leaf's MLS signature key
}
```

## API

- `MlsLeafCredential.issue(signer, signaturePublicKey)` returns the identity
  bytes for a new leaf. `MlsLeafSigner(owner, identityKey, deviceKey)` holds
  the two `KeyPair`s and signs nothing else.
- `MlsLeafCredential.verify(identity, signaturePublicKey)` returns the
  `{ identityId, deviceCredential }` owner once both signatures verify.
- `MlsLeafCredential.ownerOf(identity)` returns the owner the bytes name
  without checking signatures. Use it only for leaves already verified on
  their way into the tree.

`MlsKeyPackage.generate` issues this credential, and `MlsGroup` verifies it for
every leaf a commit, welcome or key package brings in.

## Validation and limits

Decoding is strict, and any failure throws `InvalidMlsCredentialError` with a
fixed message that never echoes input:

- at most 1024 bytes of fatal UTF-8;
- exactly four NUL-separated parts;
- `identityId` and `deviceCredential` match the exact shapes above;
- both signatures verify with strict Ed25519 (`zip215: false`) over the
  message rebuilt for the given signature key.

## Vectors

`vectors/mls-leaf-credential.json`, exported as
`@haskou/pigeon-swarm-crypto/vectors/mls-leaf-credential.json`, holds:

- deterministic test keys as PKCS#8 PEMs;
- one valid credential with its owner and signature key;
- negative cases. A case with an `owner` is well formed: `ownerOf` returns
  that owner, but `verify` must reject it.

`yarn test:mls-group-codecs` checks the vectors in Node and Chromium.
