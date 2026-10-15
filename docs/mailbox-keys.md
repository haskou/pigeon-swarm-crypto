# Mailbox keys, envelopes and authorship

Direct messages and contact presence travel through blind mailboxes. A node
stores opaque bodies under a mailbox id and only releases them to holders of a
read token. Every value below is derived on the client from a 256-bit
`SymmetricKey`; nodes never see the root.

## Key schedule

`MailboxKeySchedule.derive(root, recipient, epoch)` returns frozen
`MailboxInboxKeys`. Each field is HKDF-SHA-256 without salt, 32 bytes, with
`info = label || UTF-8(recipient) || u32be(epoch)`:

| Field | Label | Encoding |
| --- | --- | --- |
| `envelopeKey` | `pigeon/mailbox/envelope/v1` | bytes |
| `mailboxId` | `pigeon/mailbox/id/v1` | unpadded base64url |
| `postToken` | `pigeon/mailbox/post/v1` | unpadded base64url |

`recipient` is a non-empty well-formed string of at most 4096 UTF-8 bytes.
`epoch` is an integer in `[0, 2^32 - 1]`. `contactPresence(conversationKey,
recipient)` first derives `HKDF(conversationKey, info =
"pigeon/contact-presence/v1")` and then runs the schedule at epoch `0`.

## Read tokens

`MailboxReadToken.derive(root, mailboxId)` is HKDF-SHA-256 without salt over
`"pigeon/mailbox/read/v1" || mailboxId`. `deriveDevice(root, mailboxId,
credential)` binds one device credential with `"pigeon/mailbox/device-read/v1"
|| u32be(len(mailboxId)) || mailboxId || credential`. The mailbox id must be
canonical base64url of 32 bytes; the credential is a non-empty well-formed
string of at most 4096 UTF-8 bytes. Tokens are 32-byte unpadded base64url.

## Envelopes

`MailboxEnvelope.seal(keys, envelopeId, plaintext)` pads the plaintext to the
smallest bucket in `1024, 4096, 16384, 65536` bytes, so a node learns only the
bucket. The frame is `u32be(length) || plaintext || zeros`, filling
`bucket - 28` bytes. AES-256-GCM encrypts the frame with a fresh random 96-bit
IV per envelope and the AAD `${mailboxId}.${envelopeId}`. The wire body is
unpadded base64url of `iv || ciphertext || tag`, exactly
`ceil(bucket * 4 / 3)` characters. The envelope id is canonical base64url of 16
bytes. Plaintexts above `MAX_PLAINTEXT_BYTES` (65504) are refused.

`open` rejects any body that is not canonical base64url, is not exactly one
bucket long, fails authentication, declares a length beyond the bucket, or
carries non-zero padding. Every rejection throws the same
`InvalidMailboxEnvelopeError`.

## Own-record authorship (v2)

`MailboxRecordAuthorship.tag(root, record)` lets a device recognise records it
wrote to its own history mailbox. The tag key is HKDF-SHA-256 without salt,
`info = "pigeon/mailbox/own-record/v2"`. The tag is HMAC-SHA-256 over the
strict canonical JSON of the whole record, with keys sorted at every depth, as
32-byte unpadded base64url. `verify` compares in constant time and returns
`false` for any malformed input.

Version 1 serialised the record with `JSON.stringify(record,
Object.keys(record).sort())`. The replacer array also filtered nested objects,
so fields such as poll `options[].text` were not authenticated. Version 1 tags
do not verify; there is no fallback reader.

## Vectors

`vectors/mailbox-key-schedule.json`, `vectors/mailbox-read-token.json`,
`vectors/mailbox-envelope.json` and `vectors/mailbox-record-authorship.json`
pin outputs and invalid inputs. Seal vectors list the IV that the test injects.
