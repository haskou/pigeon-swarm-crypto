const honestKey =
  '78899ded7ed71ce8c18552165d02ac87bd63b91191952c4e90798f2430542b7e';
const nonCanonicalIdentity = `ee${'ff'.repeat(30)}7f`;
const identitySignature = `01${'00'.repeat(63)}`;

module.exports = [
  {
    name: 'honest known-answer signature',
    publicKey: honestKey,
    message: 'message',
    signature:
      'd05e6ca2a45dab9011f4cb2dbb45c293ab74909103e0680f074a8748ec946a76c9edf57575ac7b6d79d162163e38b1cfab1376df84379ca7e96ee6ee16af6305',
    valid: true,
  },
  {
    name: 'small-order public key with identity signature',
    publicKey: `01${'00'.repeat(31)}`,
    message: 'message',
    signature: identitySignature,
    valid: false,
  },
  {
    name: 'small-order public key for another message',
    publicKey: `01${'00'.repeat(31)}`,
    message: 'anything',
    signature: identitySignature,
    valid: false,
  },
  {
    name: 'non-canonical identity public key',
    publicKey: nonCanonicalIdentity,
    message: 'message',
    signature: identitySignature,
    valid: false,
  },
  {
    name: 'non-canonical R under the honest key',
    publicKey: honestKey,
    message: 'message',
    signature: `${nonCanonicalIdentity}bb9dc62ee84724b85b0fa54b6ad67c83b0835966a3ca39f2ca6f22f15f6b1b0f`,
    valid: false,
  },
  {
    name: 'truncated signature under the honest key',
    publicKey: honestKey,
    message: 'message',
    signature: identitySignature.slice(2),
    valid: false,
  },
  {
    name: 'truncated public key',
    publicKey: honestKey.slice(2),
    message: 'message',
    signature: identitySignature,
    valid: false,
  },
];
