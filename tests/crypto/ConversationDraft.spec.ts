import {
  ConversationDraft,
  InvalidConversationDraftError,
  SymmetricKey,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import vectors from '../../vectors/conversation-draft.json';

describe('ConversationDraft', () => {
  const [first] = vectors.cases;
  const root = SymmetricKey.fromBase64(first.root);
  const aad = (draftKey: string): string =>
    `pigeon/conversation-draft/v1:${draftKey}`;

  afterEach(() => jest.restoreAllMocks());

  it.each(vectors.cases)(
    'seals and opens the draft of $conversationId',
    ({ content, conversationId, draftKey, encryptedPayload, iv, root: value }) => {
      const key = SymmetricKey.fromBase64(value);
      jest
        .spyOn(CryptoAdapter, 'randomBytes')
        .mockReturnValueOnce(Buffer.from(iv, 'base64'));

      expect(ConversationDraft.draftKey(key, conversationId)).toBe(draftKey);
      expect(ConversationDraft.seal(key, conversationId, content)).toBe(
        encryptedPayload,
      );

      const opened = ConversationDraft.open(key, draftKey, encryptedPayload);

      expect(opened).toEqual({ content, conversationId });
      expect(opened).toBeFrozen();
    },
  );

  it('binds the draft to its root key and draft key', () => {
    const otherRoot = SymmetricKey.fromBase64(vectors.cases[1].root);

    expect(() =>
      ConversationDraft.open(otherRoot, first.draftKey, first.encryptedPayload),
    ).toThrow(new InvalidConversationDraftError());
    expect(() =>
      ConversationDraft.open(
        root,
        ConversationDraft.draftKey(root, 'other'),
        first.encryptedPayload,
      ),
    ).toThrow(InvalidConversationDraftError);
  });

  it.each([
    [
      'a reordered payload',
      JSON.stringify({ conversationId: first.conversationId, content: 'x' }),
    ],
    [
      'a non-string content',
      JSON.stringify({ content: 1, conversationId: first.conversationId }),
    ],
    [
      'a non-string conversation id',
      JSON.stringify({ content: 'x', conversationId: 1 }),
    ],
    [
      'another conversation',
      JSON.stringify({ content: 'x', conversationId: 'other' }),
    ],
    ['a non-object payload', 'null'],
  ])('refuses %s', (_, plaintext) => {
    const payload = root
      .encrypt(plaintext, { aad: aad(first.draftKey) })
      .valueOf();

    expect(() => ConversationDraft.open(root, first.draftKey, payload)).toThrow(
      InvalidConversationDraftError,
    );
  });

  it.each([
    ['a short draft key', first.draftKey.slice(1)],
    ['a padded draft key', `${first.draftKey}=`],
    ['a non-string draft key', 1],
  ])('refuses %s', (_, draftKey) => {
    expect(() =>
      ConversationDraft.open(root, draftKey as string, first.encryptedPayload),
    ).toThrow(InvalidConversationDraftError);
  });

  it('refuses malformed payloads', () => {
    expect(() =>
      ConversationDraft.open(root, first.draftKey, 'v1.aes-256-gcm.x'),
    ).toThrow(InvalidConversationDraftError);
  });

  it.each([
    ['an empty conversation id', root, '', 'x'],
    ['an oversized conversation id', root, 'a'.repeat(4097), 'x'],
    ['a non-string content', root, 'conversation-1', 1],
    ['a raw root key', Buffer.alloc(32), 'conversation-1', 'x'],
  ])('refuses to seal %s', (_, key, conversationId, content) => {
    expect(() =>
      ConversationDraft.seal(
        key as SymmetricKey,
        conversationId,
        content as string,
      ),
    ).toThrow(InvalidConversationDraftError);
  });

  it.each([
    ['an empty conversation id', root, ''],
    ['a raw root key', Buffer.alloc(32), 'conversation-1'],
  ])('refuses a draft key for %s', (_, key, conversationId) => {
    expect(() =>
      ConversationDraft.draftKey(key as SymmetricKey, conversationId),
    ).toThrow(InvalidConversationDraftError);
  });
});
