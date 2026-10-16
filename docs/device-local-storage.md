# Device-local storage keys

These formats protect data that a client keeps on the device or exports to the
user. Each one derives a purpose-bound key from a 256-bit `SymmetricKey` root
and uses AES-256-GCM with a fresh random 96-bit IV per operation. Callers never
choose IVs.

## Device root rows

`DeviceRootRowKeys.derive(root, label, identityId)` derives two keys with
HKDF-SHA-256 and `salt = "${label}:salt"`:

- the row key, `info = "${label}:v1:${identityId}"`;
- the tag key, `info = "${label}:tag:v1:${identityId}"`.

`label` is lowercase kebab-case, up to 64 characters. `identityId` is a
non-empty well-formed string of at most 4096 UTF-8 bytes.

`seal(purpose, scope, plaintext)` returns `iv || ciphertext || tag`. The AAD is
`JSON.stringify([purpose, identityId, ...scope])`, which binds a row to its
store purpose, owner and position, for example the conversation and record id
of a direct-history row. `purpose` matches `^[a-z][a-z-]{0,31}$` and cannot be
`canary`. The AAD is at most 16384 bytes and the plaintext at most 64 MiB.
`open` returns `undefined` when a row does not authenticate, so stores can skip
rows from another identity or label. Invalid purpose or scope arguments throw
`InvalidDeviceRootRowError`.

`sealCanary()` and `opensCanary(sealed)` check that a root unlocks a store. The
canary uses the AAD `["canary", identityId]` and the plaintext
`${label}:canary`.

`tag(parts)` is HMAC-SHA-256 under the tag key over `JSON.stringify(parts)`,
as 32-byte unpadded base64url. Stores use it as a deterministic, non-reversible
index key. The message is at most 16384 bytes.

## Conversation drafts

`ConversationDraft.draftKey(root, conversationId)` is an HMAC-SHA-256 of the
conversation id under `HKDF(root, info = "pigeon/conversation-draft-key/v1")`,
encoded as 32-byte unpadded base64url. Stores index drafts by this key, not by
conversation id.

`seal(root, conversationId, content)` encrypts
`JSON.stringify({content, conversationId})` with `SymmetricKey.encrypt` and the
AAD `pigeon/conversation-draft/v1:${draftKey}`. `open(root, draftKey,
payload)` requires the exact serialisation and a conversation id that derives
the same draft key, then returns frozen `{content, conversationId}`.
Conversation ids are non-empty and at most 4096 UTF-8 bytes.

## History backup files

`HistoryBackupFile.seal(root, identityId, plaintext)` derives
`HKDF(root, salt = "pigeon-swarm:history-backup:salt", info =
"pigeon-swarm:history-backup:v1:${identityId}")` and encrypts with the AAD
`JSON.stringify(["pigeon-swarm-backup", 1, identityId])`. The file is the
exact JSON `{"ciphertext","format":"pigeon-swarm-backup","iv","version":1}`
with unpadded base64url values. `open` rejects any other key order, whitespace,
format, version or encoding. The plaintext is at most 128 MiB.

## Device unlock factor

`DeviceUnlockFactor.context(identityId, deviceId, secretHandle)` is
`pigeon-swarm:device-unlock-factor:v1` and the three components joined by
`\n`. Each component is non-empty, at most 4096 UTF-8 bytes and contains no
newline. Clients also use the context as AAD for the material it protects.

`derive(factorKey, identityId, deviceId, secretHandle)` signs the context with
a WebCrypto HMAC-SHA-256 key of 256 bits that allows `sign`, and returns a
`UserRootKeySecondFactor`. The key may and should be non-extractable.

## Vectors

`vectors/device-root-rows.json`, `vectors/conversation-draft.json`,
`vectors/history-backup.json` and `vectors/device-unlock-factor.json` pin every
output. Seal vectors list the IV that the test injects.
