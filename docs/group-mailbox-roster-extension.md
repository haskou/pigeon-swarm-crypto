# Group mailbox roster extension

`GroupMailboxRosterExtension` (entry point `@haskou/pigeon-swarm-crypto/mls`)
is the GroupContext extension `0xf421` of a group conversation's MLS group,
an RFC 9420 §17.3 private-use extension. Every member agrees on the
GroupContext, so every member judges a commit by the same roster.

## Format

The extension data is the UTF-8 RFC 8785 canonical JSON of exactly these
keys:

| Key              | Value                                                                                    |
| ---------------- | ---------------------------------------------------------------------------------------- |
| `adminIds`       | Sorted, distinct identity ids. Every one is a member and none is the creator.            |
| `conversationId` | `group:` followed by an unpadded base64url SHA-256 digest (43 canonical characters).     |
| `creatorId`      | The creator's identity id. It must be a member.                                           |
| `memberIds`      | Sorted, distinct identity ids: 1 to 256 entries.                                          |
| `name`           | 1 to 80 UTF-16 code units, no surrounding whitespace, no lone surrogates.                 |
| `version`        | `1`.                                                                                     |

Each identity id is 1 to 1024 code units, with no surrounding whitespace and
no lone surrogates. Lists hold at most 256 entries.

## API

- `GroupMailboxRosterExtension.encode(fields)` sorts both lists, then
  validates and encodes the roster.
- `GroupMailboxRosterExtension.decode(bytes)` returns the
  `GroupMailboxRosterFields`.
- `GroupMailboxRosterExtension.read(extensions)` decodes a GroupContext that
  holds exactly this one extension.
- `EXTENSION_TYPE` is `0xf421` and `MAX_BYTES` is `1_048_576`.

## Validation

Every failure throws `InvalidMlsExtensionError` with a fixed message:

- more than `MAX_BYTES`, or invalid UTF-8 or JSON;
- a missing or extra key, or a field breaking the rules above;
- text that is not byte-for-byte the canonical encoding of the decoded
  roster: whitespace, key or list order, or escapes;
- for `read`: no extension, more than one, or another extension type.

Honest encodings are byte-identical to the pre-library UI encoder. The
library also rejects a lone surrogate, which the UI decoder accepted.

## Vectors

`vectors/group-mailbox-roster-extension.json` holds:

- valid cases, each with `fields`, an optional unsorted `input`, and
  `encoded`;
- negative encodings.

`yarn test:mls-group-codecs` checks them in Node and Chromium.
