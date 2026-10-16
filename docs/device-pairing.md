# Device pairing

Device pairing enrolls a new device through three signed messages and a short
authentication string (SAS). The package builds and verifies every preimage;
the application transports the messages, checks expiry and replay, and asks
both users to compare the code.

## Messages

Each message is RFC 8785 canonical JSON `{domain, <member>: payload}` encoded as
UTF-8 and signed with Ed25519 by the PEM credential the payload names. `sign`
refuses any other key and `verify` requires the given key to be that
credential.

| Class                              | Domain                                | Member       | Signer             | Fields                                                                                                    |
| ---------------------------------- | ------------------------------------- | ------------ | ------------------ | --------------------------------------------------------------------------------------------------------- |
| `DevicePairingInvitationSignature` | `pigeon:device-pairing:invitation:v1` | `invitation` | `authorCredential` | `authorCredential, epoch, expiresAt, identityId, pairingId, revision, version`                            |
| `DevicePairingRequestSignature`    | `pigeon:device-pairing:request:v1`    | `request`    | `targetCredential` | `authorizedAt, invitation, operationId, proofOfPossession, targetCredential, transportPublicKey, version` |
| `DevicePairingCompletionSignature` | `pigeon:device-pairing:completion:v1` | `completion` | `authorCredential` | `authorCredential, encryptedMaterial, epoch, identityId, operationId, pairingId, revision, version`       |

Shapes are closed. `version` is `1`; `expiresAt`, `authorizedAt` and `revision`
are safe nonnegative integers; credentials and transport keys are Ed25519 SPKI
PEMs; `identityId` is a PEM body; `proofOfPossession` is a canonical signature;
the encoded `invitation` holds at most `MAX_INVITATION_LENGTH` (32768)
characters. The distinct domains stop a message of one kind from verifying as
another.

## Verification code

`DevicePairingVerificationCode.of({operationId, pairingId, targetCredential,
transportPublicKey})` hashes the canonical JSON of those fields plus
`domain: 'pigeon:device-pairing:verification:v1'` with SHA-256, reads the first
8 bytes as a big-endian integer, reduces it modulo 10^10 and prints two
zero-padded groups of five digits, such as `75339 81070`. Both devices must show
the same code before the user approves the request.

## Errors

Every failure is `InvalidDevicePairingError` with no input, cause or nested
message.

## Verification

`vectors/device-pairing.json` holds each message with its signing content and
signature, the verification codes and rejected cases (wrong signer, tampering
and cross-domain reuse). Unit tests reproduce them byte for byte, and
`yarn test:signed-preimages` checks agreement between Node and Chromium.
