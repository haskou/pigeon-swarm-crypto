import {
  DeviceRootRowKeys,
  InvalidDeviceRootRowError,
  SymmetricKey,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import vectors from '../../vectors/device-root-rows.json';

const bytes = (value: string): Buffer => Buffer.from(value, 'base64url');

describe('DeviceRootRowKeys', () => {
  const [first] = vectors.cases;
  const root = SymmetricKey.fromBase64(first.root);
  const keys = DeviceRootRowKeys.derive(root, first.label, first.identityId);
  const sealed = bytes(first.rows[1].sealed);

  afterEach(() => jest.restoreAllMocks());

  describe.each(vectors.cases)('$label', ({ canary, identityId, label, root: value, rows, tags }) => {
    const rowKeys = DeviceRootRowKeys.derive(
      SymmetricKey.fromBase64(value),
      label,
      identityId,
    );

    it('seals and opens the canary', () => {
      jest.spyOn(CryptoAdapter, 'randomBytes').mockReturnValueOnce(bytes(canary.iv));

      expect(Buffer.from(rowKeys.sealCanary()).toString('base64url')).toBe(
        canary.sealed,
      );
      expect(rowKeys.opensCanary(bytes(canary.sealed))).toBeTrue();
    });

    it.each(rows)('seals and opens a $purpose row', ({ iv, plaintext, purpose, scope, sealed: row }) => {
      jest.spyOn(CryptoAdapter, 'randomBytes').mockReturnValueOnce(bytes(iv));

      expect(
        Buffer.from(rowKeys.seal(purpose, scope, bytes(plaintext))).toString(
          'base64url',
        ),
      ).toBe(row);
      expect(
        Buffer.from(rowKeys.open(purpose, scope, bytes(row))!).toString(
          'base64url',
        ),
      ).toBe(plaintext);
    });

    it.each(tags)('tags $parts', ({ parts, tag }) => {
      expect(rowKeys.tag(parts)).toBe(tag);
    });
  });

  it('binds every row to its purpose, scope, identity and label', () => {
    const other = DeviceRootRowKeys.derive(root, first.label, 'other-identity');
    const otherLabel = DeviceRootRowKeys.derive(
      root,
      vectors.cases[1].label,
      first.identityId,
    );
    const { purpose, scope } = first.rows[1];

    expect(keys.open('record', scope, sealed)).toBeUndefined();
    expect(keys.open(purpose, [...scope, 'x'], sealed)).toBeUndefined();
    expect(other.open(purpose, scope, sealed)).toBeUndefined();
    expect(otherLabel.open(purpose, scope, sealed)).toBeUndefined();
    expect(keys.opensCanary(sealed)).toBeFalse();
    expect(other.opensCanary(bytes(first.canary.sealed))).toBeFalse();
  });

  it.each([
    ['a non-byte row', 'sealed'],
    ['a truncated row', sealed.subarray(0, 27)],
    ['an oversized row', new Uint8Array(64 * 1024 * 1024 + 29)],
  ])('does not open %s', (_, row) => {
    const { purpose, scope } = first.rows[1];

    expect(keys.open(purpose, scope, row as Uint8Array)).toBeUndefined();
    expect(keys.opensCanary(row as Uint8Array)).toBeFalse();
  });

  it.each([
    ['the canary purpose', 'canary', []],
    ['an upper-case purpose', 'Row', []],
    ['a long purpose', `r${'o'.repeat(32)}`, []],
    ['a non-string purpose', 7, []],
    ['a non-array scope', 'row', 'scope'],
    ['a non-string scope part', 'row', [1]],
    ['an oversized scope', 'row', ['a'.repeat(16384)]],
  ])('rejects %s', (_, purpose, scope) => {
    expect(() =>
      keys.seal(purpose as string, scope as string[], new Uint8Array()),
    ).toThrow(new InvalidDeviceRootRowError());
    expect(() =>
      keys.open(purpose as string, scope as string[], sealed),
    ).toThrow(InvalidDeviceRootRowError);
  });

  it.each([
    ['a non-byte plaintext', 'plaintext'],
    ['an oversized plaintext', new Uint8Array(64 * 1024 * 1024 + 1)],
  ])('refuses to seal %s', (_, plaintext) => {
    expect(() => keys.seal('row', [], plaintext as Uint8Array)).toThrow(
      InvalidDeviceRootRowError,
    );
  });

  it('refuses to seal the canary without randomness', () => {
    jest.spyOn(CryptoAdapter, 'randomBytes').mockImplementationOnce(() => {
      throw new Error('no entropy');
    });

    expect(() => keys.sealCanary()).toThrow(InvalidDeviceRootRowError);
  });

  it.each([
    ['a non-array', 'parts'],
    ['a non-string part', [null]],
    ['an oversized message', ['a'.repeat(16384)]],
  ])('refuses to tag %s', (_, parts) => {
    expect(() => keys.tag(parts as string[])).toThrow(InvalidDeviceRootRowError);
  });

  it.each([
    ['an empty label', root, '', first.identityId],
    ['an upper-case label', root, 'Pigeon', first.identityId],
    ['a trailing dash label', root, 'pigeon-', first.identityId],
    ['a long label', root, 'a'.repeat(65), first.identityId],
    ['a non-string label', root, 1, first.identityId],
    ['an empty identity', root, first.label, ''],
    ['an oversized identity', root, first.label, 'a'.repeat(4097)],
    ['a raw root', Buffer.alloc(32), first.label, first.identityId],
  ])('refuses to derive with %s', (_, key, label, identityId) => {
    expect(() =>
      DeviceRootRowKeys.derive(
        key as SymmetricKey,
        label as string,
        identityId as string,
      ),
    ).toThrow(InvalidDeviceRootRowError);
  });
});
