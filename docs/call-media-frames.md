# Call media frames

`CallMediaFrameSealer` and `CallMediaFrameOpener` encrypt encoded audio and
video frames end to end inside WebRTC insertable streams, so relays and SFUs
only forward ciphertext. Each frame is bound to its call, sender, key epoch,
sealer, sequence number and track, and each authenticated frame opens at most
once.

## Sealing

```ts
const sealer = await CallMediaFrameSealer.create(callKey, {
  callId,
  epoch,
  senderId,
});
const frame = await sealer.seal(encodedFrame, 'video');
```

`callKey` is a 256-bit `SymmetricKey`, normally the group call key exported by
`MlsGroup.callMediaKey(callId)`. `epoch` is the epoch of that key: the MLS
epoch for group calls, or a counter the caller increments on every rekey. Use
one sealer per call, sender and epoch, shared by every track of the sender,
and create a new sealer when the key changes.

`create` picks a random 8-byte sealer id and derives the sealer's frame key
and nonce base. Sealers never collide on a nonce: their keys differ by sealer
id, and within a sealer every frame takes the next sequence number, including
concurrent `seal` calls. A sealer refuses to seal past sequence 2^53 - 1.

## Opening

```ts
const opener = CallMediaFrameOpener.create({ callId, senderId });

await opener.addKey(callKey, epoch);
const encodedFrame = await opener.open(frame, 'video');
```

Use one opener per call and remote sender. `addKey` takes keys in strictly
increasing epoch order and holds the two newest, so frames sealed before a
rekey still open until the sender switches. Once a frame of the newest held
epoch authenticates, older epochs are dropped. A key whose import fails leaves
its epoch unusable; add the next epoch instead.

`open` refuses, with `InvalidCallMediaFrameError`:

- frames without the `PSCE2` marker, shorter than 41 bytes, or longer than
  8 MiB plus 41 bytes;
- frames of an epoch the opener does not hold;
- frames that do not authenticate under the opener's call id, sender id and
  the given track, including any change to the header;
- sequences above 2^53 - 1, sequences at or below the highest authenticated
  sequence of the sealer minus 1024, and sequences already opened;
- frames of a new sealer once 64 sealers of the epoch have authenticated.

Frames within the 1024-frame window may arrive out of order. A sequence or
sealer is only recorded after its frame authenticates, so forged frames do not
consume sequences or sealer slots; of two concurrent copies of a frame, only
one opens.

## Trust model

Every member of the call holds the same call key. Frames authenticate against
the key, not against a sender: the sender id binds a frame to the opener it was
sealed for, but it does not prove who sealed it. Any holder of the call key can
therefore:

- seal frames under another member's sender id, which every opener for that
  member accepts as theirs;
- create up to 64 sealers under another member's sender id in an epoch, after
  which openers for that member refuse the member's own new sealers until the
  next epoch.

The replay window, the sealer cap and the epoch rules only stop parties without
a held call key: relays, SFUs, and former members once the opener has dropped
the epochs they knew. Removing a misbehaving member takes a rekey that excludes
them. Per-sender frame signatures, which would stop members from impersonating
each other, are out of scope.

## Format

```text
header = "PSCE2" || epoch (u32 BE) || sealer id (8 bytes) || sequence (u64 BE)
frame  = header || AES-256-GCM ciphertext || tag (16 bytes)
AAD    = header || UTF-8(track)
```

The header is 25 bytes, so a sealed frame is 41 bytes longer than its
plaintext. Plaintexts are at most 8 MiB.

| Input     | Rule                                      |
| --------- | ----------------------------------------- |
| call id   | UTF-8, 1 to 256 bytes, no lone surrogates |
| sender id | UTF-8, 1 to 256 bytes, no lone surrogates |
| track     | UTF-8, 1 to 64 bytes, no lone surrogates  |
| epoch     | integer, 0 to 2^32 - 1                    |
| sequence  | integer, 0 to 2^53 - 1, starts at 0       |

## Keys and nonces

Both sides import the call key once as a non-extractable HKDF `CryptoKey` and
overwrite their decoded copy of the key bytes with zeros. Per sealer they derive,
with HKDF-SHA256 and an empty salt:

```text
context    = u16 BE len(callId) || callId || u16 BE len(senderId) || senderId
             || epoch (u32 BE) || sealer id
frame key  = HKDF(callKey, info = "pigeon/call-media-frame/v2/key" || context)
             as a non-extractable AES-256-GCM key, encrypt-only for sealers
             and decrypt-only for openers
nonce base = HKDF(callKey, info = "pigeon/call-media-frame/v2/nonce" || context)
             as 96 bits
nonce      = (nonce base + sequence) mod 2^96, as 12 bytes big-endian
```

Encryption runs on the platform's native AES-GCM. The classes work in Node,
browsers and dedicated workers.

`vectors/call-media-frame.json` pins the call key, context, sealer id, nonce
base and the frames at sequences 0, 1 and 2 on three tracks, plus a frame at
sequence 2^53 - 1.
