import {
  DeviceAuthorizationTransitionSignature,
  type DeviceAuthorizationTransitionPreimage,
  InvalidDeviceAuthorizationTransitionError,
  PrivateKey,
  Signature,
} from '../../src';
import { loadVectors, privateKeyOf, publicKeyOf, VectorKey } from '../vectors';

type Signer = 'author' | 'recoveryAuthority';
type SignedTransition = DeviceAuthorizationTransitionPreimage & {
  proofOfPossession?: string;
  signature: string;
};
type TransitionVectors = {
  cases: {
    expected: {
      proofOfPossessionPayload: string | null;
      signingPayload: string;
      transition: SignedTransition;
    };
    name: string;
    signer: Signer;
  }[];
  credentials: { revoked: string };
  keys: Record<Signer | 'target', VectorKey>;
};

const vectors = loadVectors<TransitionVectors>(
  'device-authorization-transition',
);
const split = ({
  proofOfPossession,
  signature,
  ...transition
}: SignedTransition) => ({
  proof:
    proofOfPossession === undefined
      ? undefined
      : new Signature(proofOfPossession),
  signature: new Signature(signature),
  transition,
});
const caseNamed = (operation: string) =>
  split(
    vectors.cases.find(
      ({ expected }) => expected.transition.operation === operation,
    )!.expected.transition,
  );
const enroll = caseNamed('enroll');
const revoke = caseNamed('revoke');
const recover = caseNamed('recover');
const author = publicKeyOf(vectors.keys.author);
const recoveryAuthority = publicKeyOf(vectors.keys.recoveryAuthority);
const verifyEnroll = (transition: unknown) => () =>
  DeviceAuthorizationTransitionSignature.verify(
    transition as DeviceAuthorizationTransitionPreimage,
    enroll.proof,
    enroll.signature,
    author,
  );

describe('DeviceAuthorizationTransitionSignature', () => {
  it.each(vectors.cases)('reproduces $name', ({ expected, signer }) => {
    const { proof, signature, transition } = split(expected.transition);

    expect(
      DeviceAuthorizationTransitionSignature.signingContent(transition, proof),
    ).toBe(expected.signingPayload);
    expect(
      DeviceAuthorizationTransitionSignature.sign(
        transition,
        proof,
        privateKeyOf(vectors.keys[signer]),
      ).valueOf(),
    ).toBe(signature.valueOf());
    expect(() =>
      DeviceAuthorizationTransitionSignature.verify(
        transition,
        proof,
        signature,
        publicKeyOf(vectors.keys[signer]),
      ),
    ).not.toThrow();

    if (expected.proofOfPossessionPayload === null) return;
    expect(
      DeviceAuthorizationTransitionSignature.proofOfPossessionContent(
        transition,
      ),
    ).toBe(expected.proofOfPossessionPayload);
    expect(
      DeviceAuthorizationTransitionSignature.provePossession(
        transition,
        privateKeyOf(vectors.keys.target),
      ).valueOf(),
    ).toBe(proof!.valueOf());
  });

  it('binds the proof of possession to the target credential', () => {
    expect(() =>
      DeviceAuthorizationTransitionSignature.provePossession(
        enroll.transition,
        privateKeyOf(vectors.keys.author),
      ),
    ).toThrow(new InvalidDeviceAuthorizationTransitionError());
    expect(() =>
      DeviceAuthorizationTransitionSignature.verify(
        enroll.transition,
        recover.proof,
        enroll.signature,
        author,
      ),
    ).toThrow(new InvalidDeviceAuthorizationTransitionError());
  });

  it('requires a proof of possession exactly when the target is added', () => {
    expect(() =>
      DeviceAuthorizationTransitionSignature.signingContent(enroll.transition),
    ).toThrow(InvalidDeviceAuthorizationTransitionError);
    expect(() =>
      DeviceAuthorizationTransitionSignature.signingContent(
        revoke.transition,
        enroll.proof,
      ),
    ).toThrow(InvalidDeviceAuthorizationTransitionError);
    expect(() =>
      DeviceAuthorizationTransitionSignature.proofOfPossessionContent(
        revoke.transition,
      ),
    ).toThrow(InvalidDeviceAuthorizationTransitionError);
  });

  it('binds enrollments and revocations to the author credential', () => {
    const stranger = PrivateKey.generate();

    expect(() =>
      DeviceAuthorizationTransitionSignature.sign(
        revoke.transition,
        undefined,
        privateKeyOf(vectors.keys.recoveryAuthority),
      ),
    ).toThrow(InvalidDeviceAuthorizationTransitionError);
    expect(() =>
      DeviceAuthorizationTransitionSignature.verify(
        revoke.transition,
        undefined,
        stranger.sign(
          DeviceAuthorizationTransitionSignature.signingContent(
            revoke.transition,
          ),
        ),
        stranger.getPublicKey(),
      ),
    ).toThrow(InvalidDeviceAuthorizationTransitionError);
    expect(() =>
      DeviceAuthorizationTransitionSignature.verify(
        recover.transition,
        recover.proof,
        recover.signature,
        author,
      ),
    ).toThrow(InvalidDeviceAuthorizationTransitionError);
    expect(() =>
      DeviceAuthorizationTransitionSignature.verify(
        recover.transition,
        recover.proof,
        recover.signature,
        recoveryAuthority,
      ),
    ).not.toThrow();
  });

  const caps = (since: number[]) =>
    since.map((compromisedSince) => ({
      compromisedSince,
      credential: vectors.credentials.revoked,
    }));

  it.each([
    ['an unknown operation', { operation: 'rotate' }],
    ['a skipped revision', { revision: 3 }],
    ['a mismatched commitment', { targetCredentialCommitment: 'ff' }],
    ['a PEM identity id', { identityId: vectors.keys.author.publicKeyPem }],
    ['an enrollment without author', { authorCredential: undefined }],
    ['an enrollment without pairing', { pairingId: undefined }],
    ['an enrollment with compromisedSince', { compromisedSince: 0 }],
    ['an enrollment with caps', { compromisedCredentials: caps([0]) }],
    ['an unknown field', { extra: true }],
  ])('rejects %s', (_name, overrides) => {
    expect(verifyEnroll({ ...enroll.transition, ...overrides })).toThrow(
      new InvalidDeviceAuthorizationTransitionError(),
    );
  });

  it.each([
    [
      'a recovery with an author',
      { authorCredential: enroll.transition.authorCredential },
    ],
    ['an empty caps list', { compromisedCredentials: [] }],
    [
      'a cap newer than the previous revision',
      { compromisedCredentials: caps([9]) },
    ],
    ['duplicate caps', { compromisedCredentials: caps([0, 1]) }],
    [
      'a cap with an unknown field',
      { compromisedCredentials: [{ ...caps([0])[0], x: 1 }] },
    ],
  ])('rejects %s', (_name, overrides) => {
    expect(() =>
      DeviceAuthorizationTransitionSignature.signingContent(
        { ...recover.transition, ...overrides },
        recover.proof,
      ),
    ).toThrow(new InvalidDeviceAuthorizationTransitionError());
  });

  it('rejects a revocation compromised after its previous revision', () => {
    expect(() =>
      DeviceAuthorizationTransitionSignature.signingContent({
        ...revoke.transition,
        compromisedSince: revoke.transition.previousRevision + 1,
      }),
    ).toThrow(new InvalidDeviceAuthorizationTransitionError());
  });

  it('caps the number of compromised credentials', () => {
    const credentials = Array.from(
      {
        length:
          DeviceAuthorizationTransitionSignature.MAX_COMPROMISED_CREDENTIALS +
          1,
      },
      () => PrivateKey.generate().getPublicKey().valueOf(),
    )
      .sort()
      .map((credential) => ({ compromisedSince: 0, credential }));

    expect(() =>
      DeviceAuthorizationTransitionSignature.signingContent(
        { ...recover.transition, compromisedCredentials: credentials },
        recover.proof,
      ),
    ).toThrow(new InvalidDeviceAuthorizationTransitionError());
    expect(() =>
      DeviceAuthorizationTransitionSignature.signingContent(
        {
          ...recover.transition,
          compromisedCredentials: credentials.slice(1),
        },
        recover.proof,
      ),
    ).not.toThrow();
  });
});
