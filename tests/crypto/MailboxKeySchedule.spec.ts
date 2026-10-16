import {
  InvalidMailboxKeyError,
  MailboxKeySchedule,
  MailboxReadToken,
  SymmetricKey,
} from '../../src';
import scheduleVectors from '../../vectors/mailbox-key-schedule.json';
import readTokenVectors from '../../vectors/mailbox-read-token.json';

const encode = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64url');

describe('MailboxKeySchedule', () => {
  const secret = SymmetricKey.fromBase64(
    scheduleVectors.derive[0].sharedSecret,
  );
  const recipient = scheduleVectors.derive[0].recipientIdentityId;

  it.each(scheduleVectors.derive)(
    'derives the inbox keys of epoch $epoch',
    ({ envelopeKey, epoch, mailboxId, postToken, recipientIdentityId, sharedSecret }) => {
      const keys = MailboxKeySchedule.derive(
        SymmetricKey.fromBase64(sharedSecret),
        recipientIdentityId,
        epoch,
      );

      expect(keys).toBeFrozen();
      expect(encode(keys.envelopeKey)).toBe(envelopeKey);
      expect(keys.mailboxId).toBe(mailboxId);
      expect(keys.postToken).toBe(postToken);
    },
  );

  it.each(scheduleVectors.contactPresence)(
    'derives the contact presence inbox',
    ({ conversationKey, envelopeKey, mailboxId, postToken, recipientIdentityId }) => {
      const keys = MailboxKeySchedule.contactPresence(
        SymmetricKey.fromBase64(conversationKey),
        recipientIdentityId,
      );

      expect(encode(keys.envelopeKey)).toBe(envelopeKey);
      expect(keys.mailboxId).toBe(mailboxId);
      expect(keys.postToken).toBe(postToken);
    },
  );

  it.each([
    ['an empty recipient', ''],
    ['a non-string recipient', 7],
    ['a recipient longer than 4096 characters', 'a'.repeat(4097)],
    ['a recipient longer than 4096 bytes', 'é'.repeat(2049)],
    ['a lone surrogate', 'a\uD800'],
  ])('rejects %s', (_, value) => {
    expect(() =>
      MailboxKeySchedule.derive(secret, value as string, 0),
    ).toThrow(new InvalidMailboxKeyError());
    expect(() =>
      MailboxKeySchedule.contactPresence(secret, value as string),
    ).toThrow(InvalidMailboxKeyError);
  });

  it.each([-1, 4294967296, 1.5, Number.NaN, '1'])(
    'rejects the epoch %p',
    (epoch) => {
      expect(() =>
        MailboxKeySchedule.derive(secret, recipient, epoch as number),
      ).toThrow(InvalidMailboxKeyError);
    },
  );

  it('rejects secrets that are not symmetric keys', () => {
    const raw = Buffer.alloc(32) as unknown as SymmetricKey;

    expect(() => MailboxKeySchedule.derive(raw, recipient, 0)).toThrow(
      InvalidMailboxKeyError,
    );
    expect(() => MailboxKeySchedule.contactPresence(raw, recipient)).toThrow(
      InvalidMailboxKeyError,
    );
  });

  it('never echoes the rejected input', () => {
    try {
      MailboxKeySchedule.derive(secret, 'secret-recipient\uD800', 0);
    } catch (error) {
      expect((error as Error).message).toBe('Invalid mailbox key input');
      expect((error as Error).name).toBe('InvalidMailboxKeyError');
    }
    expect.assertions(2);
  });
});

describe('MailboxReadToken', () => {
  const rootKey = SymmetricKey.fromBase64(readTokenVectors.derive[0].rootKey);
  const mailboxId = readTokenVectors.derive[0].mailboxId;

  it.each(readTokenVectors.derive)(
    'derives the shared read token',
    ({ mailboxId: id, readToken, rootKey: root }) => {
      expect(MailboxReadToken.derive(SymmetricKey.fromBase64(root), id)).toBe(
        readToken,
      );
    },
  );

  it.each(readTokenVectors.deriveDevice)(
    'derives the device read token',
    ({ deviceCredential, mailboxId: id, readToken, rootKey: root }) => {
      expect(
        MailboxReadToken.deriveDevice(
          SymmetricKey.fromBase64(root),
          id,
          deviceCredential,
        ),
      ).toBe(readToken);
    },
  );

  it.each([
    ['an empty id', ''],
    ['a short id', mailboxId.slice(1)],
    ['a padded id', `${mailboxId}=`],
    ['a standard base64 id', mailboxId.replace(/-/g, '+').replace(/_/g, '/')],
    ['a non-string id', 1],
  ])('rejects %s', (_, id) => {
    expect(() => MailboxReadToken.derive(rootKey, id as string)).toThrow(
      new InvalidMailboxKeyError(),
    );
    expect(() =>
      MailboxReadToken.deriveDevice(rootKey, id as string, 'device'),
    ).toThrow(InvalidMailboxKeyError);
  });

  it.each([
    ['an empty credential', ''],
    ['a credential longer than 4096 bytes', 'a'.repeat(4097)],
    ['a non-string credential', null],
  ])('rejects %s', (_, credential) => {
    expect(() =>
      MailboxReadToken.deriveDevice(rootKey, mailboxId, credential as string),
    ).toThrow(InvalidMailboxKeyError);
  });

  it('rejects root keys that are not symmetric keys', () => {
    const raw = Buffer.alloc(32) as unknown as SymmetricKey;

    expect(() => MailboxReadToken.derive(raw, mailboxId)).toThrow(
      InvalidMailboxKeyError,
    );
    expect(() =>
      MailboxReadToken.deriveDevice(raw, mailboxId, 'device'),
    ).toThrow(InvalidMailboxKeyError);
  });
});
