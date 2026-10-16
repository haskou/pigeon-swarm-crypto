# MLS groups

`MlsGroup` (entry point `@haskou/pigeon-swarm-crypto/mls`) is one MLS group as
one device sees it, over `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` with
private handshake messages. Communities and group conversations run on it, so
applications import neither `ts-mls` nor a patched copy of it.

The application keeps the authority: an `MlsMembershipPolicy` decides who may
hold a leaf and which membership changes are allowed. The group enforces those
decisions on every commit it makes or takes.

## Building blocks

| Class                                | Role                                                                                                                                                          |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MlsKeyPackage`                      | `generate(signer, extensionTypes)` creates a key package whose leaf carries an `MlsLeafCredential` and lists the private-use extension types it supports. `restore(publicBytes, privatePackage)` and `ownerOf(publicBytes)` verify that credential. |
| `MlsPrivateKeyPackage`               | The private half of a key package. Keep it encrypted at rest.                                                                                                |
| `MlsLeafSigner`                      | The identity and device `KeyPair`s that vouch for a leaf signature key.                                                                                      |
| `MlsMembershipPolicy`                | `frontier`, `admits`, `reach`, `priority`, `allows` and `withheld`: the application's roster rules.                                                          |
| `MlsRosterFrontier`                  | The roster frontier every commit and welcome binds. See [mls-roster-frontier.md](mls-roster-frontier.md).                                                    |
| `GroupMailboxRosterExtension`        | The `0xf421` roster of a group conversation. See [group-mailbox-roster-extension.md](group-mailbox-roster-extension.md).                                     |

## Lifecycle

- `MlsGroup.create(groupId, key, policy, extensions)` starts a group with this
  device alone.
- `MlsGroup.join(groupId, key, welcome, policy)` accepts a welcome only when:
  - its GroupInfo carries exactly one `0xf420` frontier extension;
  - the group id matches;
  - every leaf's credential verifies;
  - the policy admits every identity at that frontier.
- `MlsGroup.restore(groupId, owner, policy, serialized, frontier)` reloads a
  stored state.
- `add`, `changeContext`, `removeIdentities`, `removeDevices` and `update`
  each build one commit. The commit binds the policy frontier as its
  authenticated data and as the GroupInfo `0xf420` extension. Each call
  returns `{ commit, epoch, welcome }` and leaves the commit pending.
  - Publish the commit, then call `confirm(recordId)`, or call `abandon()`
    when another commit won the epoch.
  - `pendingState()` exposes the state the pending commit leads to, so the
    caller can keep it before publishing.
- `applyCommit({ id, epoch, bytes })` judges a published commit and returns
  one of these outcomes:

  | Outcome    | Meaning                                                                                                  |
  | ---------- | -------------------------------------------------------------------------------------------------------- |
  | `applied`  | The commit was taken.                                                                                    |
  | `replaced` | The commit won the epoch over the one taken before, which is named.                                      |
  | `ignored`  | One of `duplicate`, `lost-race`, `stale` or `withheld`.                                                  |
  | `gap`      | An earlier commit is missing.                                                                            |
  | `removed`  | This device was removed.                                                                                 |

  Rival commits for one epoch rank by these keys, in order:

  1. whether the roster this device verified still allows them;
  2. the policy's `reach` of their frontier;
  3. the policy's `priority` of their change;
  4. the lower id.

  This is a total order, so every member converges on the same winner.
- Messages:
  - `encrypt`, `decrypt` and `open` handle application messages.
  - `authenticate` names the sender of a private message.
  - `exportSecret(label, context, length)` is the RFC 9420 §8.5 exporter.

Hostile input throws `InvalidMlsGroupError` with a fixed message that never
echoes input. Policy errors and programming errors pass through unchanged.
`MlsGroup.epochOf`, `frontierOf` and `groupIdOf` read public metadata from
encoded messages without a group.

## UpdatePath and GroupContextExtensions (RFC 9420 §12.4.2)

A commit that both carries a GroupContextExtensions proposal and needs an
UpdatePath must encrypt the path secrets to the provisional GroupContext. That
context already carries the new extensions, and receivers decrypt with it.

`ts-mls` 1.6.4 `createCommit` encrypts to the old GroupContext instead. As a
result, no other member can process such a commit, for example
`changeContext(extensions, removed)` that also removes a member. Every
receiver fails it as invalid.

`MlsGroup` builds its commits with an internal builder
(`src/mls/internal/MlsCommitBuilder.ts`). The builder follows `ts-mls` 1.6.4
`createCommit` for a member commit with a private wire format and the
ratchet-tree GroupInfo extension. It differs in three ways:

- the UpdatePath is encrypted to the provisional context;
- it commits only the proposals it is given, by value, so the membership
  policy has judged every change; stored proposals are never referenced;
- external commits and ReInit proposals are refused, and `ts-mls` refuses a
  commit that removes its own committer.

`yarn test:mls-group` runs the regression in Node and Chromium: one member
commits a GroupContextExtensions proposal together with an UpdatePath, and
another member processes it.

Delete the builder and return to `createCommit` once a stable `ts-mls` release
carries the fix.

## Tests

`yarn test:mls-group` runs every group scenario in Node and in Chromium and
checks that both runtimes pass the same list. The scenarios cover:

- create, join and restore;
- add, remove, update and context changes;
- commit races and duplicates, gaps and stale commits;
- withheld roster operations;
- hostile welcomes and commits;
- message authentication, and the exporter.
