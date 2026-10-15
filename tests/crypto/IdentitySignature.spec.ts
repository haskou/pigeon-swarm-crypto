import {
  DeviceCredentialCommitment,
  IdentitySignature,
  type IdentitySignaturePayload,
  InvalidIdentitySignatureError,
  PublicKey,
  Signature,
} from '../../src';
import { loadVectors, privateKeyOf, publicKeyOf, VectorKey } from '../vectors';

type Signer = 'device' | 'identity' | 'recovery';
type Signed = IdentitySignaturePayload & { signature: string };
type IdentityVectors = {
  cases: {
    derived: { signature: string; signingPayload: string };
    input: IdentitySignaturePayload;
    name: string;
    signer: Signer;
  }[];
  identities: {
    accepted: { name: string; primitives: Signed }[];
    rejected: {
      name: string;
      primitives: Signed;
      signedPayload: string;
      signer: Signer;
    }[];
  };
  keys: Record<Signer, VectorKey>;
};

const vectors = loadVectors<IdentityVectors>('identity-signature');
const identityKey = publicKeyOf(vectors.keys.identity);
const unsigned = ({ signature, ...payload }: Signed) => ({
  payload,
  signature: new Signature(signature),
});
const full = vectors.cases[1].input;
const verifying = (payload: unknown) => () =>
  IdentitySignature.verify(
    payload as IdentitySignaturePayload,
    new Signature(vectors.cases[1].derived.signature),
    identityKey,
  );

describe('IdentitySignature', () => {
  it.each(vectors.cases)('reproduces $name', ({ derived, input, signer }) => {
    expect(IdentitySignature.signingContent(input)).toBe(
      derived.signingPayload,
    );
    expect(
      IdentitySignature.sign(
        input,
        privateKeyOf(vectors.keys[signer]),
      ).valueOf(),
    ).toBe(derived.signature);
    expect(() =>
      IdentitySignature.verify(
        input,
        new Signature(derived.signature),
        identityKey,
      ),
    ).not.toThrow();
  });

  it.each(vectors.identities.accepted)('accepts $name', ({ primitives }) => {
    const { payload, signature } = unsigned(primitives);

    expect(() =>
      IdentitySignature.verify(payload, signature, identityKey),
    ).not.toThrow();
  });

  it.each(vectors.identities.rejected)(
    'rejects $name',
    ({ primitives, signer }) => {
      const { payload, signature } = unsigned(primitives);

      expect(() =>
        IdentitySignature.verify(
          payload,
          signature,
          publicKeyOf(vectors.keys[signer]),
        ),
      ).toThrow(new InvalidIdentitySignatureError());
    },
  );

  it('commits to the device credential PEM', () => {
    expect(
      DeviceCredentialCommitment.of(new PublicKey(full.deviceCredential)),
    ).toBe(full.deviceCredentialCommitment);
  });

  it('refuses to sign with a key other than the identity', () => {
    expect(() =>
      IdentitySignature.sign(full, privateKeyOf(vectors.keys.device)),
    ).toThrow(new InvalidIdentitySignatureError());
  });

  it.each([
    ['an unknown field', { ...full, extra: 1 }],
    ['a missing field', { ...full, networks: undefined }],
    ['a PEM identity id', { ...full, id: identityKey.valueOf() }],
    ['a mismatched commitment', { ...full, deviceCredentialCommitment: '0' }],
    ['an invalid recovery authority', { ...full, recoveryAuthority: 'x' }],
    ['a non-string network', { ...full, networks: [1] }],
    ['a non-array networks list', { ...full, networks: 'net' }],
    ['a profile without name', { ...full, profile: { handle: 'ada' } }],
    ['an unknown profile field', { ...full, profile: { name: 'A', x: 'y' } }],
    ['a non-string profile field', { ...full, profile: { name: 'A', bio: 1 } }],
    ['a non-string mailbox home', { ...full, mailboxHome: 1 }],
    ['a fractional timestamp', { ...full, timestamp: 0.5 }],
    ['a non-object payload', 'payload'],
  ])('rejects %s', (_name, payload) => {
    expect(verifying(payload)).toThrow(new InvalidIdentitySignatureError());
    expect(() =>
      IdentitySignature.signingContent(payload as IdentitySignaturePayload),
    ).toThrow(InvalidIdentitySignatureError);
  });
});
