# TURN credentials

`TurnRestCredential` issues the time-limited credentials that coturn validates with
`use-auth-secret`, following the TURN REST API convention.

```ts
const { username, credential } = TurnRestCredential.issue(
  sharedSecret,
  expiresAtSeconds,
  user,
);
const subject = TurnRestCredential.peerSubject(sharedSecret, peerId);
```

`username` is `<expiresAtSeconds>:<user>` and `credential` is standard padded
Base64 of HMAC-SHA1 keyed by the UTF-8 shared secret over the UTF-8 username. These
bytes are fixed by coturn and cannot be versioned.

`peerSubject` gives a relay peer an opaque TURN user name: the first 32 lowercase
hex characters of HMAC-SHA256 keyed by the shared secret over
`pigeon.turn.subject.v2`, one zero byte and the peer id. It does not reveal the peer
id to the TURN server's logs.

## Limits

The shared secret has 1 to 4096 UTF-16 code units without lone surrogates. The
expiry is a positive safe integer in seconds. `user` is 1 to 512 printable ASCII
characters other than `:`. Peer ids are 1 to 256 printable ASCII characters. Every
failure throws `InvalidTurnCredentialError` with a fixed message.

## Application responsibilities

The application chooses the lifetime, keeps the shared secret out of logs and
responses, and enforces relay quotas and URL limits. Anyone holding the shared
secret can mint credentials, so give it only to the TURN server and the issuer.

## Verification

`vectors/turn-credentials.json` holds known answers and rejected inputs.
`yarn test:network-derivations` reproduces them in Node and Chromium and checks
the credential against native WebCrypto HMAC-SHA1.
