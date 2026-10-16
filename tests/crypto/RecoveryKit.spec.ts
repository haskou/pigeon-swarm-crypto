import { inspect } from 'node:util';

import { InvalidRecoveryKeyError, RecoveryKey, RecoveryKit } from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import vectors from '../../vectors/recovery-kit.json';

describe('RecoveryKey', () => {
  const [first] = vectors.derive;

  afterEach(() => jest.restoreAllMocks());

  it('parses a canonical recovery key', () => {
    const key = RecoveryKey.fromString(first.recoveryKey);

    expect(key.valueOf()).toBe(first.recoveryKey);
    expect(Buffer.from(key.getBytes()).toString('base64url')).toBe(
      first.recoveryKey.slice('psrk1.'.length),
    );
    expect(key.isEqual(RecoveryKey.fromString(first.recoveryKey))).toBeTrue();
    expect(key.isEqual(first.recoveryKey)).toBeFalse();
    expect(RecoveryKey.isValid(first.recoveryKey)).toBeTrue();
  });

  it('returns a fresh copy of its bytes', () => {
    const key = RecoveryKey.fromString(first.recoveryKey);
    key.getBytes().fill(0);

    expect(Buffer.from(key.getBytes()).toString('base64url')).toBe(
      first.recoveryKey.slice('psrk1.'.length),
    );
  });

  it('generates a random recovery key and wipes the source bytes', () => {
    const random = Buffer.alloc(32, 7);
    jest.spyOn(CryptoAdapter, 'randomBytes').mockReturnValueOnce(random);
    const key = RecoveryKey.generate();

    expect(key.valueOf()).toBe(
      `psrk1.${Buffer.alloc(32, 7).toString('base64url')}`,
    );
    expect(random).toEqual(Buffer.alloc(32));
    expect(RecoveryKey.generate().isEqual(RecoveryKey.generate())).toBeFalse();
  });

  it('never serialises or inspects to its value', () => {
    const key = RecoveryKey.fromString(first.recoveryKey);

    expect(() => JSON.stringify({ key })).toThrow(
      new InvalidRecoveryKeyError(),
    );
    expect(inspect(key)).not.toContain(first.recoveryKey.slice(6));
    expect(Object.keys(key)).toEqual([]);
  });

  it.each([
    ['a non-string value', 1],
    ['a missing prefix', first.recoveryKey.slice(6)],
    ['another prefix', `psrk2.${first.recoveryKey.slice(6)}`],
    ['surrounding whitespace', ` ${first.recoveryKey} `],
    ['a short key', first.recoveryKey.slice(0, -1)],
    ['a padded key', `${first.recoveryKey}=`],
    ['a standard base64 key', `psrk1.${Buffer.alloc(32, 0xfb).toString('base64')}`],
  ])('rejects %s', (_, value) => {
    expect(() => RecoveryKey.fromString(value as string)).toThrow(
      InvalidRecoveryKeyError,
    );
    expect(RecoveryKey.isValid(value)).toBeFalse();
  });
});

describe('RecoveryKit', () => {
  it.each(vectors.derive)(
    'derives the recovery material of $recoveryKey',
    ({ identityKeyPair, recoveryAuthorityKeyPair, recoveryKey, rootKey }) => {
      const material = RecoveryKit.derive(RecoveryKey.fromString(recoveryKey));

      expect(material).toBeFrozen();
      expect(material.identityKeyPair.toPrimitives()).toEqual(identityKeyPair);
      expect(material.recoveryAuthorityKeyPair.toPrimitives()).toEqual(
        recoveryAuthorityKeyPair,
      );
      expect(material.rootKey.getBuffer().toString('base64')).toBe(rootKey);
    },
  );

  it('rejects values that are not recovery keys', () => {
    expect(() =>
      RecoveryKit.derive(vectors.derive[0].recoveryKey as never),
    ).toThrow(new InvalidRecoveryKeyError());
  });
});
