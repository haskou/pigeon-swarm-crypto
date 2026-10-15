# Private network keys

`PrivateNetworkKeys`, `PrivateNetworkPubSubEnvelope` and
`PrivateNetworkRelayRecordEnvelope` derive every secret that members of a private
Pigeon Swarm network share from the network's Ed25519 private key. Applications pass
the `PrivateKey`; they never hash, slice or re-encode its PEM.

## Interface

```ts
const fingerprint = PrivateNetworkKeys.fingerprint(networkKey);
const lookupKey = PrivateNetworkKeys.relayLookupKey(networkKey);
const swarmKey = PrivateNetworkKeys.swarmKey(networkKey); // libp2p PSK file bytes

const envelope = PrivateNetworkPubSubEnvelope.seal(
  networkKey,
  networkId,
  topic,
  payload,
);
const payload = PrivateNetworkPubSubEnvelope.open(
  networkKey,
  networkId,
  topic,
  envelope,
);

const sealedRecord = PrivateNetworkRelayRecordEnvelope.seal(networkKey, record);
const record = PrivateNetworkRelayRecordEnvelope.open(networkKey, sealedRecord);
```

## Derivation

Every value is HKDF-SHA256 with the 32-byte Ed25519 seed as input keying material,
an empty salt and one UTF-8 label as `info`. Each label has exactly one purpose:

| Label                                    | Length   | Output                                                           |
| ---------------------------------------- | -------- | ---------------------------------------------------------------- |
| `pigeon.private-network.fingerprint.v2`  | 12 bytes | Unpadded base64url, 16 characters                                |
| `pigeon.private-network.relay-lookup.v2` | 32 bytes | `pigeon-swarm/private-relays/v2/` followed by unpadded base64url |
| `pigeon.private-network.swarm-psk.v2`    | 32 bytes | `/key/swarm/psk/1.0.0/\n/base16/\n` followed by lowercase hex    |
| `pigeon.private-network.pubsub.v2`       | 32 bytes | AES-256-GCM key for pubsub envelopes                             |
| `pigeon.private-network.relay-record.v2` | 32 bytes | AES-256-GCM key for relay record envelopes                       |

These labels replace the earlier constructions outright. The earlier constructions
were SHA-256 of the PEM for the pubsub key and fingerprint, HMAC keyed by the PEM
for relay record keys and lookup, and SHA-256 of the seed for the swarm PSK. No
reader accepts them.

## Envelopes

Both envelopes are the exact JSON text
`{"ciphertext":"…","nonce":"…","version":2}`. `nonce` is 12 random bytes and
`ciphertext` is the AES-256-GCM ciphertext followed by its 16-byte tag, both in
canonical unpadded base64url. Any other key order, whitespace, extra property,
version or encoding is rejected.

Every pubsub topic of a network shares one AES-256-GCM key, and every relay record
of a network shares another. With random 96-bit nonces, a key must seal fewer than
2^32 messages over its lifetime. Rotate the network key before that.

The pubsub additional authenticated data is the UTF-8 bytes of
`pigeon.private-network.pubsub.v2`, one zero byte, and
`JSON.stringify({ networkId, topic })`. A message therefore cannot be replayed into
another network or topic. Network identifiers and topics must be 1 to 1024 UTF-16
code units without lone surrogates. Payloads are well-formed UTF-8 up to 1 MiB.

The relay record additional authenticated data is the UTF-8 relay record label.
The plaintext is RFC 8785 canonical JSON of the closed shape
`{expiresAt, issuedAt, multiaddrs, peerId, role: "relay", version: 1}`:
nonnegative safe-integer timestamps with `issuedAt < expiresAt`, 1 to 32 non-empty
multiaddrs of at most 2048 code units, a base58 peer id of at most 128 characters,
and at most 8 KiB in total. `open` returns a frozen record.

## Errors

Failures throw `InvalidPrivateNetworkKeyError`, `InvalidPrivateNetworkMessageError`
or `InvalidPrivateNetworkRelayRecordError` with a fixed message and no cause. A
wrong key, network, topic, nonce or tag is indistinguishable from malformed input.

## Application responsibilities

Members of one private network must agree on the network identifier as well as
the key. Applications decide when a network is private and must then require the
sealed envelope; accepting cleartext from a private network is a downgrade. The
application keeps relay record freshness, peer authorization and topic routing.
Never log payloads, envelopes, topics or derived values.

## Verification

`vectors/private-network.json` ships known answers produced by Node's native
crypto and negative cases for wrong keys, AAD, framing, encodings, lengths and
record shapes. `yarn test:network-derivations`, after `yarn build`, checks the
vectors in Node and in Chromium against native WebCrypto HKDF and AES-GCM.
