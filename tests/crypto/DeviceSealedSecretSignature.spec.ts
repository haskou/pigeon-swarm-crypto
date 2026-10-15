import {
  DeviceSealedSecretSignature,
  type DeviceSealedSecretPayload,
  InvalidDeviceSealedSecretError,
  Signature,
} from '../../src';
import { loadVectors, privateKeyOf, publicKeyOf, VectorKey } from '../vectors';

type Role = 'candidate' | 'identity' | 'owner' | 'recovery';
type BundlePrimitives = {
  authorizationRevision: number;
  entries: {
    recipientCredential: string;
    sealedSecret: string;
    signature: string;
  }[];
  generation: number;
  identityId: string;
  publisherCredential: string;
};
type SealedSecretVectors = {
  bundle: {
    accepted: { primitives: BundlePrimitives };
    rejected: { name: string; primitives: BundlePrimitives }[];
  };
  cases: {
    derived: { signature: string; signingPayload: string };
    input: DeviceSealedSecretPayload;
    name: string;
    signer: Role;
  }[];
  keys: Record<Role, VectorKey>;
};

const vectors = loadVectors<SealedSecretVectors>('device-sealed-secret');
const owner = publicKeyOf(vectors.keys.owner);
const pemBody = (pem: string): string =>
  pem.replace(/-----[A-Z ]+-----|\s/g, '');
const entryOf = ({ entries: [entry], ...bundle }: BundlePrimitives) => ({
  payload: {
    authorizationRevision: bundle.authorizationRevision,
    generation: bundle.generation,
    identityId: pemBody(bundle.identityId),
    publisherCredential: pemBody(bundle.publisherCredential),
    recipientCredential: pemBody(entry.recipientCredential),
    sealedSecret: entry.sealedSecret,
  },
  signature: new Signature(entry.signature),
});
const [first] = vectors.cases;

describe('DeviceSealedSecretSignature', () => {
  it.each(vectors.cases)('reproduces $name', ({ derived, input, signer }) => {
    expect(DeviceSealedSecretSignature.signingContent(input)).toBe(
      derived.signingPayload,
    );
    expect(
      DeviceSealedSecretSignature.sign(
        input,
        privateKeyOf(vectors.keys[signer]),
      ).valueOf(),
    ).toBe(derived.signature);
    expect(() =>
      DeviceSealedSecretSignature.verify(
        input,
        new Signature(derived.signature),
        owner,
      ),
    ).not.toThrow();
  });

  it('accepts the bundle entry', () => {
    const { payload, signature } = entryOf(vectors.bundle.accepted.primitives);

    expect(() =>
      DeviceSealedSecretSignature.verify(payload, signature, owner),
    ).not.toThrow();
  });

  it.each(vectors.bundle.rejected)('rejects $name', ({ primitives }) => {
    const { payload, signature } = entryOf(primitives);

    expect(() =>
      DeviceSealedSecretSignature.verify(payload, signature, owner),
    ).toThrow(new InvalidDeviceSealedSecretError());
  });

  it('binds the signature to the publisher credential', () => {
    expect(() =>
      DeviceSealedSecretSignature.sign(
        first.input,
        privateKeyOf(vectors.keys.candidate),
      ),
    ).toThrow(new InvalidDeviceSealedSecretError());
  });

  it.each([
    [
      'a PEM publisher',
      { publisherCredential: vectors.keys.owner.publicKeyPem },
    ],
    ['a non-key recipient', { recipientCredential: 'MCowBQ' }],
    ['an empty sealed secret', { sealedSecret: '' }],
    ['a fractional generation', { generation: 1.5 }],
    ['a purpose field', { purpose: 'pigeon:device-sealed-secret:v1' }],
  ])('rejects %s', (_name, overrides) => {
    expect(() =>
      DeviceSealedSecretSignature.signingContent({
        ...first.input,
        ...overrides,
      } as DeviceSealedSecretPayload),
    ).toThrow(new InvalidDeviceSealedSecretError());
  });
});
