import { createPublicKey, verify } from 'node:crypto';

import {
  EncryptedPayload,
  GroupMailboxControlLetter,
  InvalidGroupMailboxControlLetterError,
  PrivateKey,
} from '../../src';
import { loadVectors, privateKeyOf, VectorKey } from '../vectors';

interface Letter {
  conversationId: string;
  payload: string;
  recipientIdentityId: string;
  senderIdentityId: string;
  sentAt: number;
}

interface Vectors {
  keys: Record<'recipient' | 'sender' | 'stranger', VectorKey>;
  valid: {
    letter: Letter;
    name: string;
    sealed: string;
    sealedPlaintext: string;
    signature: string;
    signingContent: string;
  }[];
  invalidOpen: { name: string; sealed: string; senderIdentityId: string }[];
  invalidSeal: {
    letter: Omit<Letter, 'senderIdentityId'>;
    name: string;
  }[];
}

const vectors = loadVectors<Vectors>('group-mailbox-control-letter');
const sender = privateKeyOf(vectors.keys.sender);
const recipient = privateKeyOf(vectors.keys.recipient);
const stranger = privateKeyOf(vectors.keys.stranger);
const senderId = vectors.keys.sender.identityId;
const recipientId = vectors.keys.recipient.identityId;
const bytes = (payload: string): Uint8Array =>
  new Uint8Array(Buffer.from(payload, 'base64url'));
const inputOf = (letter: Omit<Letter, 'senderIdentityId'>) => ({
  conversationId: letter.conversationId,
  payload: bytes(letter.payload),
  recipientIdentityId: letter.recipientIdentityId,
  sentAt: letter.sentAt,
});

describe('GroupMailboxControlLetter', () => {
  it.each(vectors.valid.map((item) => [item.name, item] as const))(
    'pins the signed content of %s',
    (_name, item) => {
      expect(GroupMailboxControlLetter.signingContent(item.letter)).toBe(
        item.signingContent,
      );
      expect(
        verify(
          null,
          Buffer.from(item.signingContent, 'utf8'),
          createPublicKey(vectors.keys.sender.publicKeyPem),
          Buffer.from(item.signature, 'base64'),
        ),
      ).toBe(true);
      expect(JSON.parse(item.sealedPlaintext)).toEqual({
        ...item.letter,
        kind: 'group-mailbox-control-letter',
        signature: item.signature,
      });
    },
  );

  it.each(vectors.valid.map((item) => [item.name, item] as const))(
    'opens the shipped %s',
    (_name, item) => {
      const opened = GroupMailboxControlLetter.open(
        recipient,
        item.sealed,
        senderId,
      );

      expect(opened).toEqual({
        conversationId: item.letter.conversationId,
        payload: bytes(item.letter.payload),
        sentAt: item.letter.sentAt,
      });
      expect(opened).toBeFrozen();
    },
  );

  it.each(vectors.valid.map((item) => [item.name, item] as const))(
    'seals %s as the shipped plaintext',
    (_name, item) => {
      const sealed = GroupMailboxControlLetter.seal(
        sender,
        inputOf(item.letter),
      );

      expect(recipient.decrypt(new EncryptedPayload(sealed)).toString()).toBe(
        item.sealedPlaintext,
      );
    },
  );

  it('seals to the recipient identity with fresh randomness', () => {
    const [item] = vectors.valid;
    const first = GroupMailboxControlLetter.seal(sender, inputOf(item.letter));
    const second = GroupMailboxControlLetter.seal(sender, inputOf(item.letter));

    expect(first).not.toBe(second);
    expect(GroupMailboxControlLetter.open(recipient, second, senderId)).toEqual(
      GroupMailboxControlLetter.open(recipient, item.sealed, senderId),
    );
    expect(() =>
      GroupMailboxControlLetter.open(stranger, first, senderId),
    ).toThrow(InvalidGroupMailboxControlLetterError);
  });

  it.each(
    vectors.invalidOpen.map(
      (item) => [item.name, item.sealed, item.senderIdentityId] as const,
    ),
  )('refuses to open a letter with %s', (_name, sealed, expectedSender) => {
    expect(() =>
      GroupMailboxControlLetter.open(recipient, sealed, expectedSender),
    ).toThrow(new InvalidGroupMailboxControlLetterError());
  });

  it.each(vectors.invalidSeal.map((item) => [item.name, item.letter] as const))(
    'refuses to seal a letter with %s',
    (_name, letter) => {
      expect(() =>
        GroupMailboxControlLetter.seal(sender, inputOf(letter)),
      ).toThrow(InvalidGroupMailboxControlLetterError);
    },
  );

  it('bounds the payload and the conversation id', () => {
    const letter = {
      conversationId: 'group:x',
      payload: new Uint8Array(65536),
      recipientIdentityId: recipientId,
      sentAt: 0,
    };
    const sealed = GroupMailboxControlLetter.seal(sender, letter);

    expect(
      GroupMailboxControlLetter.open(recipient, sealed, senderId).payload,
    ).toHaveLength(65536);
    expect(() =>
      GroupMailboxControlLetter.seal(sender, {
        ...letter,
        payload: new Uint8Array(65537),
      }),
    ).toThrow(InvalidGroupMailboxControlLetterError);
    expect(() =>
      GroupMailboxControlLetter.seal(sender, {
        ...letter,
        conversationId: 'g'.repeat(257),
      }),
    ).toThrow(InvalidGroupMailboxControlLetterError);
    expect(
      GroupMailboxControlLetter.seal(sender, {
        ...letter,
        conversationId: 'g'.repeat(256),
      }),
    ).toEqual(expect.any(String));
  });

  it.each([
    ['a payload that is not bytes', { payload: 'text' }],
    ['a non-string conversation', { conversationId: 7 }],
    ['an extra field', { extra: true }],
    ['a missing time', { sentAt: undefined }],
  ])('refuses to seal %s', (_name, overrides) => {
    const letter = {
      ...inputOf(vectors.valid[0].letter),
      ...overrides,
    };

    expect(() =>
      GroupMailboxControlLetter.seal(sender, letter as never),
    ).toThrow(InvalidGroupMailboxControlLetterError);
  });

  it('refuses keys and sealed values of the wrong type', () => {
    const { letter, sealed } = vectors.valid[0];

    expect(() =>
      GroupMailboxControlLetter.seal('key' as never, inputOf(letter)),
    ).toThrow(InvalidGroupMailboxControlLetterError);
    expect(() =>
      GroupMailboxControlLetter.open(recipient, 7 as never, senderId),
    ).toThrow(InvalidGroupMailboxControlLetterError);
    expect(() =>
      GroupMailboxControlLetter.open(recipient, 'x'.repeat(524289), senderId),
    ).toThrow(InvalidGroupMailboxControlLetterError);
    expect(() =>
      GroupMailboxControlLetter.open({} as PrivateKey, sealed, senderId),
    ).toThrow(InvalidGroupMailboxControlLetterError);
  });

  it('refuses signing content for a malformed letter', () => {
    expect(() =>
      GroupMailboxControlLetter.signingContent({
        ...vectors.valid[0].letter,
        sentAt: -1,
      }),
    ).toThrow(InvalidGroupMailboxControlLetterError);
  });

  it('never echoes the input in the error', () => {
    const error = new InvalidGroupMailboxControlLetterError();

    expect(error.message).toBe('Invalid group mailbox control letter');
    expect(error.name).toBe('InvalidGroupMailboxControlLetterError');
  });
});
