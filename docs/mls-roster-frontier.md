# MLS roster frontier

`MlsRosterFrontier` (entry point `@haskou/pigeon-swarm-crypto/mls`) encodes
the roster frontier that every `MlsGroup` commit and welcome binds: the set of
community roster-log heads its committer judged the change at.

It is carried in two places:

- as the authenticated data of every commit, so the committer's leaf signs it;
- as the GroupInfo extension `0xf420` of every welcome (RFC 9420 §17.3
  private use).

## Format

```text
"pigeon:community-frontier:v1\n" || head_1 || "\n" || … || "\n" || head_n
```

Each head is the unpadded base64url SHA-256 digest of a roster operation:
43 characters, the last one from `[AEIMQUYcgkosw048]` because a 32-byte
digest leaves 4 zero bits. The heads are distinct and sorted ascending by
code unit. An empty frontier is the prefix alone.

## API

- `MlsRosterFrontier.encode(heads)` sorts the heads, then validates and
  encodes them.
- `MlsRosterFrontier.decode(bytes)` returns the heads.
- `MlsRosterFrontier.EXTENSION_TYPE` is `0xf420`.

## Validation and limits

Both directions throw `InvalidMlsExtensionError` with a fixed message on:

- more than 256 heads, or more than `29 + 256 × 44 − 1` bytes;
- a missing prefix, including empty bytes;
- a head that is not a canonical 32-byte unpadded base64url digest;
- duplicate heads, or heads that are not strictly ascending (decode only;
  encode sorts first).

Decoding is stricter than the pre-library UI reader, which accepted empty
bytes, unsorted or duplicate heads, and non-canonical last characters. An
honest encoder never produces any of them, so honest encodings are
byte-identical.

## Vectors

`vectors/mls-roster-frontier.json` holds:

- valid cases: empty, one head, an unsorted `input` with its sorted `frontier`,
  and 256 heads;
- negative encodings.

`yarn test:mls-group-codecs` checks them in Node and Chromium.
