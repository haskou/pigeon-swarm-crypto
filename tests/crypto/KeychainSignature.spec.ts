import {
  InvalidKeychainSignatureError,
  KeychainSignature,
  type KeychainSignaturePayload,
  Signature,
} from '../../src';
import { loadVectors, privateKeyOf, publicKeyOf, VectorKey } from '../vectors';

type KeychainInput = Omit<
  KeychainSignaturePayload,
  'ownerIdentityId' | 'previousKeychainExternalIdentifier'
> & { previousKeychainExternalIdentifier: string | null };
type KeychainVectors = {
  accepted: {
    expected: { signature: string; signingPayload: string };
    input: KeychainInput;
    name: string;
  }[];
  keys: Record<'owner' | 'stranger', VectorKey>;
  ownerIdentityId: string;
  rejected: { input: KeychainInput & { signature: string }; name: string }[];
};

const vectors = loadVectors<KeychainVectors>('keychain-signature');
const ownerKey = publicKeyOf(vectors.keys.owner);
const payloadOf = ({
  previousKeychainExternalIdentifier,
  ...input
}: KeychainInput): KeychainSignaturePayload => ({
  ...input,
  ownerIdentityId: vectors.ownerIdentityId,
  ...(previousKeychainExternalIdentifier === null
    ? {}
    : { previousKeychainExternalIdentifier }),
});
const [first] = vectors.accepted;
const verifying = (payload: unknown) => () =>
  KeychainSignature.verify(
    payload as KeychainSignaturePayload,
    new Signature(first.expected.signature),
    ownerKey,
  );

describe('KeychainSignature', () => {
  it.each(vectors.accepted)('reproduces $name', ({ expected, input }) => {
    const payload = payloadOf(input);

    expect(KeychainSignature.signingContent(payload)).toBe(
      expected.signingPayload,
    );
    expect(
      KeychainSignature.sign(
        payload,
        privateKeyOf(vectors.keys.owner),
      ).valueOf(),
    ).toBe(expected.signature);
    expect(() =>
      KeychainSignature.verify(
        payload,
        new Signature(expected.signature),
        ownerKey,
      ),
    ).not.toThrow();
  });

  it.each(vectors.rejected)('rejects $name', ({ input }) => {
    const { signature, ...rest } = input;

    expect(() =>
      KeychainSignature.verify(
        payloadOf(rest),
        new Signature(signature),
        ownerKey,
      ),
    ).toThrow(new InvalidKeychainSignatureError());
  });

  it('refuses keys other than the owner identity', () => {
    const payload = payloadOf(first.input);

    expect(() =>
      KeychainSignature.sign(payload, privateKeyOf(vectors.keys.stranger)),
    ).toThrow(new InvalidKeychainSignatureError());
    expect(() =>
      KeychainSignature.verify(
        payload,
        new Signature(first.expected.signature),
        publicKeyOf(vectors.keys.stranger),
      ),
    ).toThrow(new InvalidKeychainSignatureError());
  });

  it.each([
    ['an unknown field', { extra: 1 }],
    ['a PEM owner', { ownerIdentityId: vectors.keys.owner.publicKeyPem }],
    ['a non-string payload', { encryptedPayload: 1 }],
    [
      'an empty previous identifier',
      { previousKeychainExternalIdentifier: '' },
    ],
    ['a negative version', { version: -1 }],
  ])('rejects %s', (_name, overrides) => {
    const payload = { ...payloadOf(first.input), ...overrides };

    expect(verifying(payload)).toThrow(new InvalidKeychainSignatureError());
    expect(() =>
      KeychainSignature.signingContent(payload as KeychainSignaturePayload),
    ).toThrow(new InvalidKeychainSignatureError());
  });
});
