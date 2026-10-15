import {
  InvalidKeyFingerprintError,
  InvalidSafetyNumberError,
  KeyFingerprint,
  PublicKey,
  SafetyNumber,
} from '../../src';
import fingerprintVectors from '../../vectors/key-fingerprint.json';
import safetyVectors from '../../vectors/safety-number.json';

const bytes = (value: string): Buffer => Buffer.from(value, 'base64url');

describe('SafetyNumber', () => {
  it.each(safetyVectors.cases)(
    'derives the safety number of $first and $second',
    ({ first, groups, second }) => {
      const number = SafetyNumber.between(first, second);

      expect(number).toEqual(groups);
      expect(number).toBeFrozen();
      expect(SafetyNumber.between(second, first)).toEqual(groups);
    },
  );

  it.each([
    ['an empty identity', ''],
    ['a multi-line identity', 'a\nb'],
    ['an oversized identity', 'a'.repeat(4097)],
    ['a non-string identity', 1],
  ])('rejects %s', (_, identityId) => {
    expect(() => SafetyNumber.between('a', identityId as string)).toThrow(
      new InvalidSafetyNumberError(),
    );
    expect(() => SafetyNumber.between(identityId as string, 'a')).toThrow(
      InvalidSafetyNumberError,
    );
  });
});

describe('KeyFingerprint', () => {
  it.each(fingerprintVectors.publicKeys)(
    'fingerprints the public key $fingerprint',
    ({ fingerprint, publicKey }) => {
      const pem = publicKey.startsWith('-----BEGIN')
        ? publicKey
        : `-----BEGIN PUBLIC KEY-----\n${publicKey}\n-----END PUBLIC KEY-----\n`;

      expect(KeyFingerprint.ofPublicKey(PublicKey.fromPEM(pem))).toBe(
        fingerprint,
      );
    },
  );

  it.each(fingerprintVectors.publicBytes)(
    'fingerprints public bytes as $fingerprint',
    ({ bytes: value, fingerprint }) => {
      expect(KeyFingerprint.ofPublicBytes(bytes(value))).toBe(fingerprint);
    },
  );

  it.each(fingerprintVectors.secrets)(
    'fingerprints a secret as $fingerprint',
    ({ fingerprint, secret }) => {
      expect(KeyFingerprint.ofSecret(bytes(secret))).toBe(fingerprint);
    },
  );

  it('rejects inputs that are not keys or bytes', () => {
    expect(() =>
      KeyFingerprint.ofPublicKey('MCowBQYDK2VwAyEA' as never),
    ).toThrow(new InvalidKeyFingerprintError());
    expect(() => KeyFingerprint.ofPublicBytes('bytes' as never)).toThrow(
      InvalidKeyFingerprintError,
    );
    expect(() =>
      KeyFingerprint.ofPublicBytes(new Uint8Array(65537)),
    ).toThrow(InvalidKeyFingerprintError);
    expect(() => KeyFingerprint.ofSecret('secret' as never)).toThrow(
      InvalidKeyFingerprintError,
    );
    expect(() => KeyFingerprint.ofSecret(new Uint8Array(65536))).toThrow(
      InvalidKeyFingerprintError,
    );
  });
});
