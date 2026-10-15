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

type Derive = (...args: unknown[]) => string;

const sections: Record<string, [Section, Derive]> = {
  call: [vectors.call, CommitmentId.call as Derive],
  community: [vectors.community, CommitmentId.community as Derive],
  communityChannel: [
    vectors.communityChannel,
    CommitmentId.communityChannel as Derive,
  ],
  communityRole: [vectors.communityRole, CommitmentId.communityRole as Derive],
  communityRequest: [
    vectors.communityRequest,
    CommitmentId.communityRequest as Derive,
  ],
  communityModerationLog: [
    vectors.communityModerationLog,
    CommitmentId.communityModerationLog as Derive,
  ],
  communityInviteToken: [
    vectors.communityInviteToken,
    CommitmentId.communityInviteToken as Derive,
  ],
  mlsRecord: [vectors.mlsRecord, CommitmentId.mlsRecord as Derive],
  privateBlobOwner: [
    vectors.privateBlobOwner,
    CommitmentId.privateBlobOwner as Derive,
  ],
  stateDigest: [vectors.stateDigest, StateDigest.of as Derive],
  communityFrontiers: [
    vectors.communityFrontiers as Section,
    StateDigest.communityFrontiers as Derive,
  ],
};

const run = (derive: Derive, args: unknown[]): string =>
  Reflect.apply(derive, undefined, args) as string;

describe('CommitmentId and StateDigest shipped vectors', () => {
  describe.each(Object.entries(sections))('%s', (_, [section, derive]) => {
    it.each(section.valid.map((item) => [item.name, item] as const))(
      'derives %s',
      (_name, item) => {
        expect(run(derive, item.args)).toBe(item.id);
      },
    );

    it.each(section.invalid.map((item) => [item.name, item.args] as const))(
      'rejects %s',
      (_name, args) => {
        expect(() => run(derive, args)).toThrow(InvalidCommitmentError);
      },
    );
  });

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
  });

  it('never reaches a non-canonical MLS record preimage', () => {
    for (const item of vectors.mlsRecord.distinct) {
      expect(
        CommitmentId.mlsRecord(JSON.parse(item.preimage) as never),
      ).not.toBe(item.id);
    }
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
