import { createHash, createHmac } from 'node:crypto';

import { CommitmentId, InvalidCommitmentError, StateDigest } from '../../src';
import vectors from '../../vectors/commitment-ids.json';

interface ValidCase {
  args: unknown[];
  id: string;
  name: string;
}

interface Section {
  invalid: { args: unknown[]; name: string }[];
  valid: ValidCase[];
}

type Owner = typeof CommitmentId | typeof StateDigest;

const sections: Record<string, [Section, Owner, string]> = {
  call: [vectors.call, CommitmentId, 'call'],
  community: [vectors.community, CommitmentId, 'community'],
  communityChannel: [
    vectors.communityChannel,
    CommitmentId,
    'communityChannel',
  ],
  communityRole: [vectors.communityRole, CommitmentId, 'communityRole'],
  communityRequest: [
    vectors.communityRequest,
    CommitmentId,
    'communityRequest',
  ],
  communityModerationLog: [
    vectors.communityModerationLog,
    CommitmentId,
    'communityModerationLog',
  ],
  communityInviteToken: [
    vectors.communityInviteToken,
    CommitmentId,
    'communityInviteToken',
  ],
  mlsRecord: [vectors.mlsRecord, CommitmentId, 'mlsRecord'],
  privateBlobOwner: [
    vectors.privateBlobOwner,
    CommitmentId,
    'privateBlobOwner',
  ],
  oneToOneConversation: [
    vectors.oneToOneConversation,
    CommitmentId,
    'oneToOneConversation',
  ],
  groupConversation: [
    vectors.groupConversation,
    CommitmentId,
    'groupConversation',
  ],
  invitation: [vectors.invitation, CommitmentId, 'invitation'],
  stateDigest: [vectors.stateDigest, StateDigest, 'of'],
  communityFrontiers: [
    vectors.communityFrontiers as Section,
    StateDigest,
    'communityFrontiers',
  ],
};

const run = (owner: Owner, method: string, args: unknown[]): string =>
  Reflect.apply(
    Reflect.get(owner, method) as (...values: unknown[]) => string,
    owner,
    args,
  );

describe('CommitmentId and StateDigest shipped vectors', () => {
  describe.each(Object.entries(sections))(
    '%s',
    (_, [section, owner, method]) => {
      it.each(section.valid.map((item) => [item.name, item] as const))(
        'derives %s',
        (_name, item) => {
          expect(run(owner, method, item.args)).toBe(item.id);
        },
      );

      it.each(section.invalid.map((item) => [item.name, item.args] as const))(
        'rejects %s',
        (_name, args) => {
          expect(() => run(owner, method, args)).toThrow(
            InvalidCommitmentError,
          );
        },
      );
    },
  );

  it('hashes exactly the documented preimage', () => {
    const sha = (text: string): Buffer =>
      createHash('sha256').update(text, 'utf8').digest();

    for (const item of vectors.communityChannel.valid)
      expect(sha(item.preimage).toString('hex').slice(0, 24)).toBe(item.id);

    for (const item of vectors.community.valid)
      expect(sha(item.preimage).toString('base64url')).toBe(item.id);

    for (const item of vectors.mlsRecord.valid)
      expect(sha(item.preimage).toString('base64url')).toBe(item.id);

    for (const item of vectors.privateBlobOwner.valid) {
      const [salt, identityId] = item.args;
      expect(
        createHmac('sha256', Buffer.from(salt, 'hex'))
          .update(identityId, 'utf8')
          .digest('hex'),
      ).toBe(item.id);
    }

    for (const item of vectors.oneToOneConversation.valid)
      expect(`one-to-one:${sha(item.preimage).toString('hex')}`).toBe(item.id);

    for (const item of vectors.groupConversation.valid)
      expect(`group:${sha(item.preimage).toString('base64url')}`).toBe(item.id);

    for (const item of vectors.invitation.valid)
      expect(`invitation:${sha(item.preimage).toString('hex')}`).toBe(item.id);
  });

  describe('group message ids', () => {
    const [author, other] = [
      vectors.groupMessage.owned[0].args[1],
      vectors.groupMessage.owned[2].args[1],
    ];

    it.each(
      vectors.groupMessage.owned.map((item) => [item.name, item.args] as const),
    )('owns %s', (_name, [id, authorId]) => {
      expect(CommitmentId.isGroupMessageOf(id, authorId)).toBe(true);
    });

    it.each(
      vectors.groupMessage.foreign.map(
        (item) => [item.name, item.args] as const,
      ),
    )('does not own %s', (_name, [id, authorId]) => {
      expect(
        CommitmentId.isGroupMessageOf(id as string, authorId as string),
      ).toBe(false);
    });

    it('creates fresh ids tagged with the documented preimage', () => {
      const id = CommitmentId.groupMessage(author);
      const [nonce, tag] = id.split('.');

      expect(id).toMatch(/^[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{22}$/);
      expect(tag).toBe(
        createHash('sha256')
          .update(['pigeon-group-message-id', author, nonce].join('\0'))
          .digest()
          .subarray(0, 16)
          .toString('base64url'),
      );
      expect(CommitmentId.isGroupMessageOf(id, author)).toBe(true);
      expect(CommitmentId.isGroupMessageOf(id, other)).toBe(false);
      expect(CommitmentId.groupMessage(author)).not.toBe(id);
    });

    it.each([
      ['an empty author', ''],
      ['a lone surrogate author', '\ud800'],
      ['a non-string author', 7],
    ])('refuses to create an id for %s', (_name, authorId) => {
      expect(() => CommitmentId.groupMessage(authorId as string)).toThrow(
        InvalidCommitmentError,
      );
    });
  });

  it('never reaches a non-canonical MLS record preimage', () => {
    for (const item of vectors.mlsRecord.distinct) {
      expect(
        CommitmentId.mlsRecord(JSON.parse(item.preimage) as never),
      ).not.toBe(item.id);
    }
  });

  it('rejects text with lone surrogates', () => {
    const salt = vectors.privateBlobOwner.valid[0].args[0];
    const derivations = [
      (): string => CommitmentId.call('\ud800', 'vector-call-nonce-conv-0001'),
      (): string => CommitmentId.community('network', 'owner', 'nonce-\udc00'),
      (): string => CommitmentId.communityRole('community', '\ud83d', 0),
      (): string => CommitmentId.privateBlobOwner(salt, '\ud800'),
      (): string =>
        StateDigest.communityFrontiers([
          { communityId: 'community', frontier: ['\udfff'] },
        ]),
    ];

    for (const derive of derivations)
      expect(derive).toThrow(InvalidCommitmentError);
  });

  it('digests bytes', () => {
    for (const item of vectors.bytesDigest.valid)
      expect(StateDigest.ofBytes(Buffer.from(item.bytes, 'hex'))).toBe(item.id);

    expect(() => StateDigest.ofBytes('bytes' as never)).toThrow(
      InvalidCommitmentError,
    );
  });

  it('rejects values that are not JSON data', () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;

    for (const value of [
      cyclic,
      { value: Number.NaN },
      { value: Number.POSITIVE_INFINITY },
      { value: 1n },
      { value: (): void => undefined },
      { value: Symbol('state') },
      { value: new Date(0) },
      { value: [undefined] },
      [],
      Object.create(null) as Record<string, unknown>,
    ])
      expect(() => StateDigest.of(value as never)).toThrow(
        InvalidCommitmentError,
      );
  });

  it('drops undefined properties like JSON', () => {
    expect(StateDigest.of({ kept: 1, dropped: undefined })).toBe(
      StateDigest.of({ kept: 1 }),
    );
  });

  it('treats an undefined optional MLS field as absent', () => {
    const content = vectors.mlsRecord.valid[0].args[0] as {
      groupId: string;
      kind: string;
      payload: string;
    };

    expect(
      CommitmentId.mlsRecord({
        ...content,
        epoch: undefined,
        recipientIdentityId: undefined,
      }),
    ).toBe(vectors.mlsRecord.valid[0].id);
  });

  it('creates a fresh node salt for private blob owners', () => {
    const salt = CommitmentId.privateBlobOwnerSalt();

    expect(salt).toMatch(/^[0-9a-f]{64}$/);
    expect(CommitmentId.privateBlobOwnerSalt()).not.toBe(salt);
    expect(CommitmentId.privateBlobOwner(salt, 'identity')).toMatch(
      /^[0-9a-f]{64}$/,
    );
  });

  it('never echoes the input in the error', () => {
    const error = new InvalidCommitmentError();

    expect(error.message).toBe('Invalid commitment');
    expect(error.name).toBe('InvalidCommitmentError');
  });
});
