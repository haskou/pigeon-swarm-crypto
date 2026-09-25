# User root key protection

`UserRootKey` is random 256-bit key material used as the root of a user's local
key hierarchy. It is never derived from a password, signing key or encryption
key. Applications derive or wrap purpose-specific keys below this boundary and
may re-protect the root without replacing those keys.

`ProtectedUserRootKey` requires a password and an independent 32-byte second
factor. Its version 1 envelope applies scrypt with `N=262144`, `r=8`, `p=1`, then
combines the result with the second factor through HKDF-SHA-256. AES-256-GCM
authenticates the version, algorithms, work factors and salt. Every protection
operation creates a new salt and IV.

Browser clients should obtain the second factor from a WebAuthn PRF credential
after user verification. The PRF result must stay local, must not be logged or
stored beside the protected envelope, and must not be sent to a node. There is no
password-only fallback in this API. Account recovery must use a separately
protected high-entropy recovery path and must rotate affected device credentials.

`rewrap` changes password and second-factor protection while preserving the
random root key. It does not rotate device credentials, conversation epochs or
history keys. Those lifecycles remain independent by design.

An attacker holding only a protected envelope cannot test passwords without the
second factor. Code executing in the same client origin while the user is
unlocked can still invoke cryptographic operations or read application memory.
Callers must also defend the client origin, dependencies, rendering boundary and
session lifetime. JavaScript cannot guarantee physical erasure of every runtime
copy, although temporary byte buffers are overwritten where the runtime permits.

Publishing a protected envelope to IPFS is still discouraged. IPFS copies are
persistent, so future implementation defects or compromise of both factors could
expose the root indefinitely. Store the envelope only in the encrypted local
vault and explicitly selected recovery storage.
