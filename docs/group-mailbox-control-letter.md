# Group mailbox control letters

A group mailbox control letter carries one control record, such as a welcome
or a membership change, from a sender identity to one recipient identity. The
sender identity signs it, and it is sealed to the recipient identity key, so a
node relaying it learns neither the record nor who sent it.

## Interface

```ts
const sealed: string = GroupMailboxControlLetter.seal(senderKey, {
  conversationId,
  payload, // Uint8Array
  recipientIdentityId,
  sentAt,
});
const { conversationId, payload, sentAt } = GroupMailboxControlLetter.open(
  recipientKey,
  sealed,
  senderIdentityId,
);
GroupMailboxControlLetter.signingContent(fields);
```

`senderKey` and `recipientKey` are the identity `PrivateKey`s. `open` returns
a frozen letter only when the expected sender signed it for this recipient.

## Format

Identity ids are the PEM bodies of the Ed25519 identity public keys. The
sender signs, with Ed25519 over UTF-8:

```text
"pigeon:group-mailbox-control-letter:v1\n" || RFC 8785 {
  conversationId, kind: "group-mailbox-control-letter", payload,
  recipientIdentityId, senderIdentityId, sentAt
}
```

`payload` is the canonical unpadded base64url of the record bytes, and the
signature is standard padded base64. The sealed plaintext is RFC 8785 of the
signed fields plus `signature`. `PublicKey.encrypt` seals it to the recipient
identity key (`v2.x25519-hkdf-sha256-aes-256-gcm`) with fresh randomness.

## Limits and validation

Every failure throws `InvalidGroupMailboxControlLetterError` with a fixed
message and no input.

- `conversationId` is a non-empty well-formed string of at most 256 UTF-8
  bytes.
- `payload` is at most `MAX_PAYLOAD_BYTES` (65536) bytes; it may be empty.
- `sentAt` is a non-negative safe integer, in milliseconds since the epoch.
- Identity ids must be PEM bodies of valid public keys; a full PEM is refused.
- `seal` accepts exactly the four draft fields.
- `open` refuses a sealed value longer than `MAX_SEALED_LENGTH` (524288)
  characters, anything that is not an asymmetric payload for this key, and a
  plaintext that is not strict canonical JSON with exactly the signed fields,
  `kind` and `signature`: duplicate keys, other key orders, padded or
  non-canonical payloads, extra or missing fields and a wrong `kind` are all
  refused.
- `open` requires `senderIdentityId` to equal the expected sender,
  `recipientIdentityId` to equal the opening key, and the signature to verify
  with the sender identity key.

A letter proves who sent it and who it is for, not that it is fresh or new.
It carries no unique nonce, so a captured sealed value opens again every time
it is delivered. Consumers must deduplicate letters and only accept a `sentAt`
within the window they allow, especially for control kinds that change
membership.

## Vectors

`vectors/group-mailbox-control-letter.json` lists valid letters with the
signing content, signature, sealed plaintext and a sealed value, and invalid
letters to open or seal. Sealed values are randomized, so tests check `seal`
by opening its output and comparing the decrypted plaintext.
