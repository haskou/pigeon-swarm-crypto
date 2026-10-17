import { createHash } from 'node:crypto';

import {
  CommitmentId,
  InvalidPublicMutationError,
  type PublicMutation,
  type PublicMutationBody,
  PublicMutationSignature,
} from '../../src';
import { loadVectors, privateKeyOf, publicKeyOf, VectorKey } from '../vectors';

type MutationCase = {
  derived: {
    mutationBody: PublicMutationBody;
    payload: unknown;
    payloadCanonical: string;
    payloadDigest: string;
    signature: string;
    signingContent: string;
  };
  name: string;
};
type MutationVectors = {
  cases: MutationCase[];
  keys: Record<string, VectorKey>;
};
type ReplicationVectors = {
  vectors: {
    name: string;
    payload: unknown;
    proofBody: PublicMutationBody;
    signingContent: string;
  }[];
};

const files = [
  'call-event',
  'community-moderation-log',
  'community-operation',
  'conversation-operation',
  'notification',
];
const cases = files.flatMap((file) => {
  const { cases: fileCases, keys } = loadVectors<MutationVectors>(file);

  return fileCases.map(({ derived, name }) => {
    const signer = Object.values(keys).find(
      ({ identityId }) =>
        identityId === derived.mutationBody.author.deviceCredential,
    ) as VectorKey;

    return { derived, file, name, signer };
  });
});
const [{ derived: sample, signer: sampleSigner }] = cases;
const sampleMutation = {
  ...sample.mutationBody,
  signature: sample.signature,
} as PublicMutation;
const replication = loadVectors<ReplicationVectors>('content-replication');
const callEvents = loadVectors<MutationVectors>('call-event').cases;
const callCase = (name: string): MutationCase =>
  callEvents.find((entry) => entry.name === name) as MutationCase;
const digest = 'A'.repeat(43);

describe('PublicMutationSignature', () => {
  it.each(cases)('reproduces $file $name', ({ derived, signer }) => {
    expect(PublicMutationSignature.payloadDigest(derived.payload)).toBe(
      derived.payloadDigest,
    );
    expect(PublicMutationSignature.signingContent(derived.mutationBody)).toBe(
      derived.signingContent,
    );

    const mutation = PublicMutationSignature.sign(
      derived.mutationBody,
      privateKeyOf(signer),
    );

    expect(mutation.signature).toBe(derived.signature);
    expect(
      PublicMutationSignature.verify(mutation, publicKeyOf(signer)),
    ).toEqual({ ...derived.mutationBody, signature: derived.signature });
  });

  it.each(replication.vectors)(
    'reproduces content replication $name',
    ({ payload, proofBody, signingContent }) => {
      expect(PublicMutationSignature.payloadDigest(payload)).toBe(
        proofBody.payloadDigest,
      );
      expect(PublicMutationSignature.signingContent(proofBody)).toBe(
        signingContent,
      );
    },
  );

  it.each(
    cases.filter(
      ({ derived, file }) =>
        file === 'notification' && 'idPreimage' in (derived as object),
    ),
  )('derives the notification id of $name', ({ derived }) => {
    const { idPreimage, payload } = derived as unknown as {
      idPreimage: string;
      payload: {
        id: string;
        inviterIdentityId: string;
        nonce: string;
        recipientIdentityId: string;
        subjectId?: string;
      };
    };

    expect(
      CommitmentId.invitation(
        payload.inviterIdentityId,
        payload.recipientIdentityId,
        payload.nonce,
        payload.subjectId,
      ),
    ).toBe(payload.id);
    expect(payload.id).toBe(
      `invitation:${createHash('sha256').update(idPreimage).digest('hex')}`,
    );
  });

  it('chains a predecessor through the mutation digest', () => {
    const joined = callCase('call_participant_joined').derived;
    const left = callCase('call_participant_left_after_joined').derived;

    expect(
      PublicMutationSignature.digest({
        ...joined.mutationBody,
        signature: joined.signature,
      }),
    ).toBe(left.mutationBody.predecessor);
  });

  it('parses a signed mutation into a frozen value', () => {
    const parsed = PublicMutationSignature.parse(sampleMutation);

    expect(parsed).toEqual(sampleMutation);
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it('creates canonical random operation ids', () => {
    const operationId = PublicMutationSignature.newOperationId();

    expect(operationId).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(PublicMutationSignature.newOperationId()).not.toBe(operationId);
  });

  it('rejects a tampered mutation', () => {
    expect(() =>
      PublicMutationSignature.verify(
        { ...sampleMutation, recordId: `${sampleMutation.recordId}x` },
        publicKeyOf(sampleSigner),
      ),
    ).toThrow(new InvalidPublicMutationError());
  });

  it('rejects a key that is not the author device', () => {
    const other = cases.find(
      ({ signer }) => signer.identityId !== sampleSigner.identityId,
    ) as (typeof cases)[number];

    expect(() =>
      PublicMutationSignature.verify(sampleMutation, publicKeyOf(other.signer)),
    ).toThrow(new InvalidPublicMutationError());
    expect(() =>
      PublicMutationSignature.sign(
        sample.mutationBody,
        privateKeyOf(other.signer),
      ),
    ).toThrow(new InvalidPublicMutationError());
  });

  it('rejects a non-canonical signature encoding', () => {
    const unpadded = sample.signature.replace(/=+$/, '');

    expect(() =>
      PublicMutationSignature.verify(
        { ...sampleMutation, signature: unpadded },
        publicKeyOf(sampleSigner),
      ),
    ).toThrow(new InvalidPublicMutationError());
  });

  it('accepts a sorted frontier', () => {
    expect(() =>
      PublicMutationSignature.signingContent({
        ...sample.mutationBody,
        frontier: [digest, 'B'.repeat(43)],
      }),
    ).not.toThrow();
  });

  it.each([
    ['an empty frontier', { frontier: [] }],
    ['an unsorted frontier', { frontier: ['B'.repeat(43), digest] }],
    ['a duplicated frontier head', { frontier: [digest, digest] }],
    [
      'too many frontier heads',
      {
        frontier: Array.from(
          { length: PublicMutationSignature.MAX_FRONTIER_HEADS + 1 },
          (_, index) => `${String(index).padStart(3, '0')}${'A'.repeat(40)}`,
        ),
      },
    ],
    ['a malformed frontier head', { frontier: ['head'] }],
    ['a genesis with a predecessor', { predecessor: digest }],
    ['a successor without a predecessor', { sequence: 1 }],
    ['a malformed predecessor', { predecessor: 'head', sequence: 1 }],
    ['an unknown kind', { kind: 'patch' }],
    ['a short operation id', { operationId: 'short' }],
    ['a malformed payload digest', { payloadDigest: 'digest' }],
    [
      'an oversized record id',
      { recordId: 'r'.repeat(PublicMutationSignature.MAX_TEXT_LENGTH + 1) },
    ],
    ['an empty store', { store: '' }],
    ['an unknown version', { version: 1 }],
    ['an unknown field', { scope: 'public' }],
    ['a signature field', { signature: sample.signature }],
    [
      'an author with an unknown field',
      { author: { ...sample.mutationBody.author, role: 'admin' } },
    ],
    [
      'a negative authorization revision',
      { author: { ...sample.mutationBody.author, authorizationRevision: -1 } },
    ],
  ])('rejects a body with %s', (_name, overrides) => {
    expect(() =>
      PublicMutationSignature.signingContent({
        ...sample.mutationBody,
        ...overrides,
      } as PublicMutationBody),
    ).toThrow(new InvalidPublicMutationError());
  });

  it.each([
    ['a missing signature', { signature: undefined }],
    ['a malformed signature', { signature: 'signature' }],
    ['an unknown field', { extra: true }],
  ])('refuses to parse a mutation with %s', (_name, overrides) => {
    expect(() =>
      PublicMutationSignature.parse({ ...sampleMutation, ...overrides }),
    ).toThrow(new InvalidPublicMutationError());
    expect(() =>
      PublicMutationSignature.digest({
        ...sampleMutation,
        ...overrides,
      } as PublicMutation),
    ).toThrow(new InvalidPublicMutationError());
  });

  it.each([
    ['a non-object', 'mutation'],
    ['an array', [sampleMutation]],
    ['null', null],
    ['a class instance', new Map(Object.entries(sampleMutation))],
  ])('refuses to parse %s', (_name, value) => {
    expect(() => PublicMutationSignature.parse(value)).toThrow(
      new InvalidPublicMutationError(),
    );
  });

  it('rejects a payload that is not canonical JSON', () => {
    expect(() => PublicMutationSignature.payloadDigest({ at: NaN })).toThrow(
      new InvalidPublicMutationError(),
    );
  });
});
