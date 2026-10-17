import {
  CommitmentId,
  CommunityOperationSignature,
  InvalidCommunityOperationSignatureError,
  Signature,
} from '../../src';
import { loadVectors, privateKeyOf, publicKeyOf, VectorKey } from '../vectors';

type CommunityOperationVectors = {
  cases: {
    derived: {
      identitySignature: string;
      identitySigningContent: string;
      digest: string;
      recordId: string;
    };
    input: { createdAt: number; signer: string };
    name: string;
  }[];
  keys: Record<string, VectorKey>;
};
type ModerationLogVectors = {
  cases: {
    derived: { id: string };
    input: {
      action: string;
      communityId: string;
      createdAt: number;
      signer: string;
      target: { id: string; type: string };
    };
    name: string;
  }[];
  keys: Record<string, VectorKey>;
};

const vectors = loadVectors<CommunityOperationVectors>('community-operation');
const [{ derived: sample, input: sampleInput }] = vectors.cases;
const owner = publicKeyOf(vectors.keys[sampleInput.signer]);
const moderationLogs = loadVectors<ModerationLogVectors>(
  'community-moderation-log',
);

describe('CommunityOperationSignature', () => {
  it.each(vectors.cases)('reproduces $name', ({ derived, input }) => {
    const signer = vectors.keys[input.signer];

    expect(CommunityOperationSignature.signingContent(derived.recordId)).toBe(
      derived.identitySigningContent,
    );
    expect(
      CommunityOperationSignature.sign(
        derived.recordId,
        privateKeyOf(signer),
      ).valueOf(),
    ).toBe(derived.identitySignature);
    expect(() =>
      CommunityOperationSignature.verify(
        derived.recordId,
        new Signature(derived.identitySignature),
        publicKeyOf(signer),
      ),
    ).not.toThrow();
  });

  it('rejects the signature of another record', () => {
    const [, other] = vectors.cases;

    expect(() =>
      CommunityOperationSignature.verify(
        other.derived.recordId,
        new Signature(sample.identitySignature),
        owner,
      ),
    ).toThrow(new InvalidCommunityOperationSignatureError());
  });

  it.each([
    ['a conversation record', sample.recordId.replace('community:', 'chat:')],
    ['a short operation digest', `${sample.recordId.slice(0, -1)}`],
    ['a trailing newline', `${sample.recordId}\n`],
  ])('rejects %s', (_name, recordId) => {
    expect(() => CommunityOperationSignature.signingContent(recordId)).toThrow(
      new InvalidCommunityOperationSignatureError(),
    );
    expect(() =>
      CommunityOperationSignature.sign(
        recordId,
        privateKeyOf(vectors.keys[sampleInput.signer]),
      ),
    ).toThrow(new InvalidCommunityOperationSignatureError());
  });

  it('names the invitation it creates by its digest in the moderation log', () => {
    const { derived, input } = vectors.cases.find(
      ({ name }) => name === 'invitation_created',
    ) as CommunityOperationVectors['cases'][number];
    const log = moderationLogs.cases.find(
      ({ name }) => name === 'invitation_created_names_operation_digest',
    ) as ModerationLogVectors['cases'][number];

    expect(derived.recordId.endsWith(`:op:${derived.digest}`)).toBe(true);
    expect(log.input.target).toEqual({
      id: derived.digest,
      type: 'invitation',
    });
    expect(log.input.createdAt).toBe(input.createdAt);
    expect(
      CommitmentId.communityModerationLog(
        log.input.communityId,
        moderationLogs.keys[log.input.signer].identityId,
        log.input.action,
        log.input.target.type,
        log.input.target.id,
        log.input.createdAt,
      ),
    ).toBe(log.derived.id);
  });
});
