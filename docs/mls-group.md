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
  stored state. It checks the group id and the owner's leaf but trusts the
  rest of the state: store it where only this device can change it, e.g.
  sealed with `ProtectedMlsGroupState`.
- `add`, `changeContext`, `removeIdentities`, `removeDevices` and `update`
  each build one commit. The commit binds the policy frontier as its
  authenticated data and as the GroupInfo `0xf420` extension. Each call
  returns `{ commit, epoch, welcome }` and leaves the commit pending.
  - Publish the commit, then call `confirm(recordId)`, or call `abandon()`
    when another commit won the epoch. `confirm` refuses, and drops the
    pending commit, once the group left the epoch it was built in or moved
    to another branch of it, e.g. because a rival replaced an earlier commit.
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

  This is a total order, so every member that verified the same roster
  converges on the same winner; the first key depends on that roster.

  A rival for an epoch more than 8 epochs behind the current one is ignored as
  `stale` (see Retention).
- Messages:
  - `encrypt`, `decrypt` and `open` handle application messages. `open`
    verifies the sender's signature and names its leaf owner.
  - `authenticate` reads the sender a private message claims from its sender
    data without verifying the signature. Any member can claim any leaf, so
    use it to route, never to authorize.
- Exported secrets (RFC 9420 §8.5 exporter, 32 bytes, bound to the current
  epoch):

  | Method                           | Label                         | Context                       |
  | -------------------------------- | ----------------------------- | ----------------------------- |
  | `callMediaKey(callId)`           | `pigeon/call-media/v1`        | UTF-8 call id, 1 to 256 bytes |
  | `groupMailboxGenerationSecret()` | `pigeon/group-mailbox/gen/v1` | empty                         |

  There is no exporter with a caller-chosen label: each purpose gets its own
  method, so labels cannot collide.

Hostile input throws `InvalidMlsGroupError` with a fixed message that never
echoes input. Policy errors and programming errors pass through unchanged.
`MlsGroup.epochOf`, `frontierOf` and `groupIdOf` read public metadata from
encoded messages without a group.

## Retention

A group keeps secrets for the current epoch and the 8 before it
(`RETAINED_EPOCHS`):

- `ts-mls` keeps the receiver data of those epochs to decrypt late messages.
- `MlsGroup` keeps the state before each commit it took for those epochs, to
  switch to a rival that wins one of them. Older states are dropped, and a
  rival for their epochs is `stale`.
- States left when stepping back are kept only until the group reaches or
  passes their epochs again.

`changes()` lists the membership changes taken since create, join or restore;
it holds no secrets and is not bounded by the window.

Dropped states are not zeroed: JavaScript cannot reliably erase memory, and
states share buffers with the live state, so zeroing one could corrupt it.
They become unreachable and the garbage collector reclaims them.

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
ratchet-tree GroupInfo extension. It differs in these ways:

- the UpdatePath is encrypted to the provisional context;
- it commits only the proposals it is given, by value, so the membership
  policy has judged every change; stored proposals are never referenced;
- external commits and ReInit proposals are refused, and `ts-mls` refuses a
  commit that removes its own committer;
- the new state is always active: `createCommit` would mark it self-removed,
  which cannot happen because that removal is refused;
- it returns no `consumed` secrets to zero (see Retention).

`yarn test:mls-group` runs the regression in Node and Chromium: one member
commits a GroupContextExtensions proposal together with an UpdatePath, and
another member processes it.

Delete the builder and return to `createCommit` once a stable `ts-mls` release
carries the fix, still refuses a commit that removes its committer, and the
regression stays green.

## Tests

`yarn test:mls-group` runs every group scenario in Node and in Chromium and
checks that both runtimes pass the same list. The scenarios cover:

- create, join and restore;
- add, remove, update and context changes;
- commit races and duplicates, gaps and stale commits;
- withheld roster operations;
- hostile welcomes and commits;
- message authentication, and the exported secrets and their labels;
- confirming after a rival replaced an earlier commit, and the retention
  window.
