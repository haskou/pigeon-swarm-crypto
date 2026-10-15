import { InvalidMailboxEnvelopeError, MailboxEnvelope } from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import vectors from '../../vectors/mailbox-envelope.json';

const bytes = (value: string): Buffer => Buffer.from(value, 'base64url');

describe('MailboxEnvelope', () => {
  const keys = {
    envelopeKey: bytes(vectors.envelopeKey),
    mailboxId: vectors.mailboxId,
  };
  const envelopeId = vectors.seal[0].envelopeId;

  afterEach(() => jest.restoreAllMocks());

  it.each(vectors.seal)(
    'seals and opens a $plaintext.length character plaintext',
    ({ body, envelopeId: id, iv, plaintext }) => {
      jest.spyOn(CryptoAdapter, 'randomBytes').mockReturnValueOnce(bytes(iv));

      expect(MailboxEnvelope.seal(keys, id, bytes(plaintext))).toBe(body);
      expect(
        Buffer.from(MailboxEnvelope.open(keys, id, body)).toString('base64url'),
      ).toBe(plaintext);
    },
  );

  it.each(vectors.invalid)('rejects $reason', ({ body, envelopeId: id }) => {
    expect(() => MailboxEnvelope.open(keys, id, body)).toThrow(
      new InvalidMailboxEnvelopeError(),
    );
  });

  it('pads every plaintext to a fixed bucket', () => {
    expect(MailboxEnvelope.BUCKETS).toEqual([1024, 4096, 16384, 65536]);
    expect(MailboxEnvelope.BUCKETS).toBeFrozen();
    expect(MailboxEnvelope.bucketFor(0)).toBe(1024);
    expect(MailboxEnvelope.bucketFor(992)).toBe(1024);
    expect(MailboxEnvelope.bucketFor(993)).toBe(4096);
    expect(MailboxEnvelope.bucketFor(MailboxEnvelope.MAX_PLAINTEXT_BYTES)).toBe(
      65536,
    );
  });

  it.each([-1, 1.5, Number.NaN, MailboxEnvelope.MAX_PLAINTEXT_BYTES + 1])(
    'rejects the plaintext length %p',
    (length) => {
      expect(() => MailboxEnvelope.bucketFor(length)).toThrow(
        InvalidMailboxEnvelopeError,
      );
    },
  );

  it('seals the largest plaintext into the largest bucket', () => {
    const plaintext = new Uint8Array(MailboxEnvelope.MAX_PLAINTEXT_BYTES).fill(
      7,
    );
    const body = MailboxEnvelope.seal(keys, envelopeId, plaintext);

    expect(body).toHaveLength(Math.ceil((65536 * 4) / 3));
    expect(MailboxEnvelope.open(keys, envelopeId, body)).toEqual(
      Buffer.from(plaintext),
    );
    expect(() =>
      MailboxEnvelope.seal(
        keys,
        envelopeId,
        new Uint8Array(MailboxEnvelope.MAX_PLAINTEXT_BYTES + 1),
      ),
    ).toThrow(InvalidMailboxEnvelopeError);
  });

  it.each([
    ['a non-byte plaintext', keys, envelopeId, 'text'],
    ['a short envelope id', keys, envelopeId.slice(1), new Uint8Array()],
    ['a padded envelope id', keys, `${envelopeId}==`, new Uint8Array()],
    [
      'a short mailbox id',
      { ...keys, mailboxId: keys.mailboxId.slice(2) },
      envelopeId,
      new Uint8Array(),
    ],
    [
      'a short envelope key',
      { ...keys, envelopeKey: keys.envelopeKey.subarray(1) },
      envelopeId,
      new Uint8Array(),
    ],
    [
      'a non-byte envelope key',
      { ...keys, envelopeKey: 'key' },
      envelopeId,
      new Uint8Array(),
    ],
  ])('refuses to seal with %s', (_, sealKeys, id, plaintext) => {
    expect(() =>
      MailboxEnvelope.seal(
        sealKeys as typeof keys,
        id,
        plaintext as Uint8Array,
      ),
    ).toThrow(InvalidMailboxEnvelopeError);
  });

  it('binds the envelope to its mailbox and key', () => {
    const { body } = vectors.seal[1];
    const otherKey = Buffer.from(keys.envelopeKey);
    otherKey[0] = otherKey[0] === 0 ? 1 : 0;

    expect(() =>
      MailboxEnvelope.open(
        { ...keys, mailboxId: Buffer.alloc(32, 1).toString('base64url') },
        vectors.seal[1].envelopeId,
        body,
      ),
    ).toThrow(InvalidMailboxEnvelopeError);
    expect(() =>
      MailboxEnvelope.open(
        { ...keys, envelopeKey: otherKey },
        vectors.seal[1].envelopeId,
        body,
      ),
    ).toThrow(InvalidMailboxEnvelopeError);
  });

  it.each([
    ['a non-string body', 42],
    ['an empty body', ''],
    ['a standard base64 body', vectors.seal[0].body.replace(/[-_]/g, '+')],
  ])('refuses to open %s', (_, body) => {
    expect(() =>
      MailboxEnvelope.open(keys, envelopeId, body as string),
    ).toThrow(InvalidMailboxEnvelopeError);
  });
});
