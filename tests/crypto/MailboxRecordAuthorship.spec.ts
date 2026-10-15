import {
  InvalidMailboxRecordAuthorshipError,
  MailboxRecordAuthorship,
  SymmetricKey,
} from '../../src';
import vectors from '../../vectors/mailbox-record-authorship.json';

describe('MailboxRecordAuthorship', () => {
  const rootKey = SymmetricKey.fromBase64(vectors.tags[0].rootKey);
  const record = vectors.tags[0].record;

  it.each(vectors.tags)(
    'tags and verifies a $record.type record',
    ({ record: value, rootKey: root, tag }) => {
      const key = SymmetricKey.fromBase64(root);

      expect(MailboxRecordAuthorship.tag(key, value)).toBe(tag);
      expect(MailboxRecordAuthorship.verify(key, value, tag)).toBeTrue();
    },
  );

  it.each(vectors.invalid)(
    'refuses $reason',
    ({ record: value, rootKey: root, tag }) => {
      expect(
        MailboxRecordAuthorship.verify(SymmetricKey.fromBase64(root), value, tag),
      ).toBeFalse();
    },
  );

  it('tags the canonical record regardless of key order', () => {
    const { record: value, rootKey: root, tag } = vectors.keyOrderIndependent;
    const key = SymmetricKey.fromBase64(root);
    const reversed = Object.fromEntries(Object.entries(value).reverse());

    expect(MailboxRecordAuthorship.tag(key, value)).toBe(tag);
    expect(MailboxRecordAuthorship.tag(key, reversed)).toBe(tag);
  });

  it('covers nested values', () => {
    const poll = vectors.tags[2].record as Record<string, unknown>;
    const options = poll.options as Record<string, unknown>[];
    const changed = {
      ...poll,
      options: [{ ...options[0], text: 'changed' }, ...options.slice(1)],
    };

    expect(
      MailboxRecordAuthorship.verify(
        SymmetricKey.fromBase64(vectors.tags[2].rootKey),
        changed,
        vectors.tags[2].tag,
      ),
    ).toBeFalse();
  });

  it.each([
    ['a non-canonical number', { ...record, createdAt: 1e400 }],
    ['a non-object record', 'record'],
    ['a lone surrogate', { ...record, id: '\uD800' }],
    [
      'an over-deep record',
      { deep: JSON.parse(`${'['.repeat(80)}${']'.repeat(80)}`) },
    ],
  ])('refuses to tag %s', (_, value) => {
    expect(() =>
      MailboxRecordAuthorship.tag(rootKey, value as Record<string, unknown>),
    ).toThrow(new InvalidMailboxRecordAuthorshipError());
    expect(
      MailboxRecordAuthorship.verify(
        rootKey,
        value as Record<string, unknown>,
        vectors.tags[0].tag,
      ),
    ).toBeFalse();
  });

  it('refuses root keys that are not symmetric keys', () => {
    const raw = Buffer.alloc(32) as unknown as SymmetricKey;

    expect(() => MailboxRecordAuthorship.tag(raw, record)).toThrow(
      InvalidMailboxRecordAuthorshipError,
    );
    expect(
      MailboxRecordAuthorship.verify(raw, record, vectors.tags[0].tag),
    ).toBeFalse();
  });

  it('refuses non-string tags', () => {
    expect(
      MailboxRecordAuthorship.verify(rootKey, record, 7 as unknown as string),
    ).toBeFalse();
  });
});
