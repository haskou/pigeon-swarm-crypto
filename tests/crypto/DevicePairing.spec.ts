import {
  DevicePairingCompletionSignature,
  type DevicePairingCompletionPayload,
  DevicePairingInvitationSignature,
  type DevicePairingInvitationPayload,
  DevicePairingRequestSignature,
  type DevicePairingRequestPayload,
  DevicePairingVerificationCode,
  type DevicePairingVerificationInput,
  InvalidDevicePairingError,
  PrivateKey,
  PublicKey,
  Signature,
} from '../../src';
import { loadVectors, privateKeyOf, publicKeyOf, VectorKey } from '../vectors';

type Role = 'author' | 'identity' | 'stranger' | 'target' | 'transport';
type Format = 'completion' | 'invitation' | 'request';
type Signed<T> = { payload: T; signature: string; signingPayload: string };
type PairingVectors = {
  completion: Signed<DevicePairingCompletionPayload>;
  invitation: Signed<DevicePairingInvitationPayload>;
  keys: Record<Role, VectorKey>;
  rejected: {
    format: Format;
    name: string;
    payload: never;
    signature: string;
    signer: Role;
  }[];
  request: Signed<DevicePairingRequestPayload>;
  verificationCodes: {
    code: string;
    input: DevicePairingVerificationInput;
    name: string;
  }[];
};
type PairingFormat = {
  sign(payload: never, key: PrivateKey): Signature;
  signingContent(payload: never): string;
  verify(payload: never, signature: Signature, key: PublicKey): void;
};

const vectors = loadVectors<PairingVectors>('device-pairing');
const formats: Record<Format, PairingFormat> = {
  completion: DevicePairingCompletionSignature,
  invitation: DevicePairingInvitationSignature,
  request: DevicePairingRequestSignature,
};
const signers: Record<Format, Role> = {
  completion: 'author',
  invitation: 'author',
  request: 'target',
};
const { invitation, request, completion } = vectors;

describe('device pairing signatures', () => {
  it.each(['invitation', 'request', 'completion'] as const)(
    'reproduces the %s',
    (format) => {
      const { payload, signature, signingPayload } = vectors[
        format
      ] as Signed<never>;
      const signer = vectors.keys[signers[format]];

      expect(formats[format].signingContent(payload)).toBe(signingPayload);
      expect(
        formats[format].sign(payload, privateKeyOf(signer)).valueOf(),
      ).toBe(signature);
      expect(() =>
        formats[format].verify(
          payload,
          new Signature(signature),
          publicKeyOf(signer),
        ),
      ).not.toThrow();
    },
  );

  it.each(vectors.rejected)(
    'rejects $name',
    ({ format, payload, signature, signer }) => {
      expect(() =>
        formats[format].verify(
          payload,
          new Signature(signature),
          publicKeyOf(vectors.keys[signer]),
        ),
      ).toThrow(new InvalidDevicePairingError());
    },
  );

  it('refuses to sign for a credential the key does not hold', () => {
    expect(() =>
      DevicePairingInvitationSignature.sign(
        invitation.payload,
        privateKeyOf(vectors.keys.target),
      ),
    ).toThrow(new InvalidDevicePairingError());
  });

  it.each([
    ['an unknown version', { version: 2 }],
    ['a PEM identity id', { identityId: invitation.payload.authorCredential }],
    ['an invalid author credential', { authorCredential: 'MCowBQ' }],
    ['an unknown field', { kind: 'invitation' }],
  ])('rejects an invitation with %s', (_name, overrides) => {
    expect(() =>
      DevicePairingInvitationSignature.signingContent({
        ...invitation.payload,
        ...overrides,
      } as DevicePairingInvitationPayload),
    ).toThrow(new InvalidDevicePairingError());
  });

  it.each([
    [
      'an oversized invitation',
      {
        invitation: 'a'.repeat(
          DevicePairingRequestSignature.MAX_INVITATION_LENGTH + 1,
        ),
      },
    ],
    ['a malformed proof of possession', { proofOfPossession: 'proof' }],
    ['a missing transport key', { transportPublicKey: undefined }],
  ])('rejects a request with %s', (_name, overrides) => {
    expect(() =>
      DevicePairingRequestSignature.signingContent({
        ...request.payload,
        ...overrides,
      } as DevicePairingRequestPayload),
    ).toThrow(new InvalidDevicePairingError());
  });

  it('accepts a request invitation of the maximum length', () => {
    expect(() =>
      DevicePairingRequestSignature.signingContent({
        ...request.payload,
        invitation: 'a'.repeat(
          DevicePairingRequestSignature.MAX_INVITATION_LENGTH,
        ),
      }),
    ).not.toThrow();
  });

  it('rejects a completion with a negative revision', () => {
    expect(() =>
      DevicePairingCompletionSignature.signingContent({
        ...completion.payload,
        revision: -1,
      }),
    ).toThrow(new InvalidDevicePairingError());
  });
});

describe('DevicePairingVerificationCode', () => {
  it.each(vectors.verificationCodes)('derives $name', ({ code, input }) => {
    expect(DevicePairingVerificationCode.of(input)).toBe(code);
  });

  it('pads codes to ten digits', () => {
    expect(vectors.verificationCodes.map(({ code }) => code)).toContain(
      '06726 76326',
    );
  });

  it.each([
    [
      'a body-only target credential',
      { targetCredential: vectors.keys.target.identityId },
    ],
    ['an empty pairing id', { pairingId: '' }],
    ['an unknown field', { domain: 'x' }],
  ])('rejects %s', (_name, overrides) => {
    expect(() =>
      DevicePairingVerificationCode.of({
        ...vectors.verificationCodes[0].input,
        ...overrides,
      } as DevicePairingVerificationInput),
    ).toThrow(new InvalidDevicePairingError());
  });
});
