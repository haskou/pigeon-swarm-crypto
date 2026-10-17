import { inspect } from 'node:util';

import {
  CommunityInvitationKey,
  CommunityInvitationPossession,
  InvalidCommunityInvitationError,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import { loadVectors } from '../vectors';

type CommunityInvitationVectors = {
  derivations: {
    invitationKey: string;
    name: string;
    secret: string;
    seedHex: string;
  }[];
  invalid: {
    invitationKeys: { invitationKey: string; name: string }[];
    secrets: { name: string; secret: string }[];
  };
  proofs: {
    fields: {
      communityId: string;
      identityId: string;
      invitationId: string;
      networkId: string;
    };
  }[];
};

const vectors = loadVectors<CommunityInvitationVectors>('community-invitation');
const [first] = vectors.derivations;

describe('CommunityInvitationKey', () => {
  afterEach(() => jest.restoreAllMocks());

  it.each(vectors.derivations)(
    'derives the invitation key of the $name',
    ({ invitationKey, secret, seedHex }) => {
      expect(CommunityInvitationKey.fromSecret(secret).publicKey()).toBe(
        invitationKey,
      );
      expect(
        Buffer.from(
          CryptoAdapter.hkdfSha256(
            Buffer.from(secret, 'base64url'),
            'pigeon:community-invitation-key:v1',
            32,
          ),
        ).toString('hex'),
      ).toBe(seedHex);
      expect(CommunityInvitationKey.parsePublicKey(invitationKey)).toBe(
        invitationKey,
      );
    },
  );

  it('wipes the secret bytes and the seed after deriving the key', () => {
    const hkdf = jest.spyOn(CryptoAdapter, 'hkdfSha256');
    CommunityInvitationKey.fromSecret(first.secret);

    expect(hkdf.mock.calls[0][0]).toEqual(new Uint8Array(32));
    expect(hkdf.mock.calls[0][1]).toBe('pigeon:community-invitation-key:v1');
    expect(hkdf.mock.results[0].value).toEqual(new Uint8Array(32));
  });

  it('generates a random secret, wipes the random bytes and derives its key', () => {
    const random = Buffer.from(first.secret, 'base64url');
    jest.spyOn(CryptoAdapter, 'randomBytes').mockReturnValueOnce(random);
    const { key, secret } = CommunityInvitationKey.generate();

    expect(secret).toBe(first.secret);
    expect(key.publicKey()).toBe(first.invitationKey);
    expect(random).toEqual(Buffer.alloc(32));
    expect(CommunityInvitationKey.generate().secret).not.toBe(
      CommunityInvitationKey.generate().secret,
    );
  });

  it('signs possession proofs that verify under its public key', () => {
    const { key } = CommunityInvitationKey.generate();
    const [{ fields }] = vectors.proofs;

    expect(() =>
      CommunityInvitationPossession.verify(
        fields,
        key.signPossession(fields),
        key.publicKey(),
      ),
    ).not.toThrow();
  });

  it('never serializes or prints the key', () => {
    const key = CommunityInvitationKey.fromSecret(first.secret);

    expect(() => JSON.stringify({ key })).toThrow(
      new InvalidCommunityInvitationError(),
    );
    expect(inspect(key, { showHidden: true })).not.toContain('PRIVATE');
  });

  it.each(vectors.invalid.secrets)(
    'refuses a secret with $name',
    ({ secret }) => {
      expect(() => CommunityInvitationKey.fromSecret(secret)).toThrow(
        new InvalidCommunityInvitationError(),
      );
    },
  );

  it.each([
    ...vectors.invalid.invitationKeys,
    { invitationKey: undefined, name: 'no value' },
    { invitationKey: 7, name: 'a number' },
  ])('refuses an invitation key with $name', ({ invitationKey }) => {
    expect(() =>
      CommunityInvitationKey.parsePublicKey(invitationKey as string),
    ).toThrow(new InvalidCommunityInvitationError());
  });
});
