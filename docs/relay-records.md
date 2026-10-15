# Relay record signatures

`CallRelayRecordSignature` and `PublicRelayRecordSignature` define the bytes that
relay peers sign with their libp2p Ed25519 identity and verify those signatures.
The application signs `signingBytes(fields)` with its libp2p private key, which
never enters this package.

```ts
const message = CallRelayRecordSignature.signingBytes(fields);
const poolSignature = CallRelayRecordSignature.poolSignature(
  fields,
  sharedSecret,
);
CallRelayRecordSignature.verify(fields, poolSignature, signature, sharedSecret);

const publicMessage = PublicRelayRecordSignature.signingBytes(fields);
PublicRelayRecordSignature.verify(fields, signature);
```

## Signed bytes

Call relay records sign the UTF-8 bytes of
`JSON.stringify({expiresAt, issuedAt, peerId, publicKey, role, urls, version})`
with that key order and `urls` sorted. Public relay records sign
`JSON.stringify({expiresAt, issuedAt, multiaddrs, peerId, publicKey, role, version})`
with `multiaddrs` sorted. Only the listed fields are signed; the signature fields
and any other property are ignored.

`publicKey` is the canonical unpadded base64url libp2p protobuf of a strict
Ed25519 public key (`08 01 12 20` followed by 32 bytes). Signatures are 64-byte
canonical unpadded base64url Ed25519 signatures verified without ZIP-215
leniency.

Version 1 call relay records also carry `poolSignature`: canonical unpadded
base64url HMAC-SHA256 keyed by the UTF-8 pool shared secret over the same JSON.
Version 2 records are peer announcements and must carry an empty pool signature.
Comparison is constant time.

## Limits

Timestamps are nonnegative safe integers with `issuedAt < expiresAt`. Peer ids are
1 to 128 base58 characters. Call relay records have 1 to 8 URLs and public relay
records 1 to 64 multiaddrs; each is 1 to 2048 code units without lone surrogates.
Roles are `call-relay` and `relay`. Failures throw `InvalidCallRelayRecordError` or
`InvalidPublicRelayRecordError` with a fixed message.

## Application responsibilities

The library checks that the signature matches the embedded public key. The
application must check that the peer id is derived from that public key, that the
record is currently within its lifetime, and that the relay is authorized.

## Verification

`vectors/relay-records.json` holds signed version 1 and version 2 call relay
records, a public relay record and tampered or malformed cases.
`yarn test:network-derivations` verifies them in Node and Chromium.
