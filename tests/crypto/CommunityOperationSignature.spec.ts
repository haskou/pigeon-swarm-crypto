import {
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
      recordId: string;
    };
    input: { signer: string };
    name: string;
  }[];
  keys: Record<string, VectorKey>;
};

const vectors = loadVectors<CommunityOperationVectors>('community-operation');
const [{ derived: sample, input: sampleInput }] = vectors.cases;
const owner = publicKeyOf(vectors.keys[sampleInput.signer]);

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
});
