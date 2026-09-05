# @haskou/pigeon-swarm-crypto

Cryptographic operations and serialized key formats used by Pigeon Swarm clients
and relay nodes. The package owns signing, encryption, password-based key
protection and digest computation. Generic value types remain in
[`@haskou/value-objects`](https://github.com/haskou/value-objects).

## Installation

```sh
yarn add @haskou/pigeon-swarm-crypto @haskou/value-objects@7
```

Import public APIs from the package root. Internal adapters are implementation
details and are not exported.

The package currently publishes CommonJS JavaScript and TypeScript declarations.
It requires Node.js 20.20.2 or newer. Browser applications need a bundler with
CommonJS and `buffer` support, and a secure context providing Web Crypto. Validate
the resulting browser bundle; successful Node.js tests alone do not establish
browser compatibility.

## Signing and asymmetric encryption

```ts
import { KeyPair } from '@haskou/pigeon-swarm-crypto';

const recipient = await KeyPair.generate();
const signature = recipient.sign('message');
const verified = recipient.isValidSignature('message', signature);
const encrypted = recipient.encrypt('confidential message');
const plaintext = recipient.decrypt(encrypted).toString('utf8');
```

Keys use Ed25519 for signatures. Asymmetric encryption converts the recipient key
to X25519 and combines ephemeral key agreement, HKDF-SHA-256 and AES-256-GCM.
Applications must authenticate the recipient's public key and define a canonical
signed message. Encryption to a public key does not authenticate the sender.

## Symmetric encryption

```ts
import { SymmetricKey } from '@haskou/pigeon-swarm-crypto';

const key = SymmetricKey.generate();
const encrypted = key.encrypt('confidential message');
const plaintext = key.decrypt(encrypted).toString('utf8');
```

`encrypt` generates a fresh nonce and returns a versioned envelope. Keep the key
separate from the ciphertext. When supplying application-specific authenticated
data through `aad`, supply exactly the same bytes during decryption. Do not invent
a new envelope or rename its version fields without a compatibility plan.

## Protecting a private key

```ts
import {
  EncryptedPrivateKey,
  PrivateKey,
} from '@haskou/pigeon-swarm-crypto';

async function protectPrivateKey(privateKey: PrivateKey, password: string) {
  return EncryptedPrivateKey.create(privateKey, password);
}

async function unlockPrivateKey(serialized: string, password: string) {
  return new EncryptedPrivateKey(serialized).decrypt(password);
}
```

New protected keys use the v3 scrypt envelope. Existing supported envelopes remain
readable. `needsReEncryption()` identifies older formats; callers decide when to
replace stored data after a successful unlock. This package does not enforce an
application password policy or provide account recovery.

## Public API

| Responsibility | Exports |
| --- | --- |
| Keys and signatures | `Key`, `PrivateKey`, `PublicKey`, `KeyPair`, `Signature` |
| Protected keys | `EncryptedPrivateKey`, `EncryptedKeyPair`, `CryptoPassword` |
| Encrypted envelopes | `EncryptedPayload`, `AsymmetricEncryptedPayload`, `SymmetricEncryptedPayload`, `EncryptedPayloadScheme` |
| Symmetric encryption | `SymmetricKey`, `SymmetricKeyCryptOptions`, `SymmetricKeyDerivationOptions` |
| Digest computation | `MD5Hash`, `SHA256Hash`, `SHA512Hash`, `HashPayload` |
| Public errors | `InvalidKeyError`, `InvalidSignatureError`, `InvalidEncryptedPrivateKeyFormatError` |

Digest classes expose `.from(payload)` for computation. The corresponding classes
in `value-objects` validate an already-computed digest. With version 7, equality
requires the same concrete type; use `hasValue` only when comparing the underlying
digest across representations intentionally. MD5 is retained for compatibility,
not for security-sensitive integrity or password storage.

## Compatibility and security

See [wire formats and migration](docs/compatibility.md) before changing imports or
persisted data, and [SECURITY.md](SECURITY.md) for security boundaries and reporting.
Moving encryption into this package does not provide forward secrecy, metadata
privacy, anonymous communication or deletion of data already replicated through
IPFS.

## Development

```bash
yarn install --frozen-lockfile
yarn lint
yarn test:coverage
yarn build
```

The test suite includes interoperability with the former UI and backend package
versions, using their actual implementations. See [CONTRIBUTING.md](CONTRIBUTING.md)
for validation and release requirements.

## License

MIT. See [LICENSE.txt](LICENSE.txt).
