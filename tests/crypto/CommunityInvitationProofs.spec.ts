import {
  CommunityInvitationConsent,
  CommunityInvitationFields,
  CommunityInvitationKey,
  CommunityInvitationPossession,
  InvalidCommunityInvitationError,
  PrivateKey,
} from '../../src';
import { loadVectors, privateKeyOf, VectorKey } from '../vectors';

type CommunityInvitationVectors = {
  invalid: {
    consents: {
      consent: string;
      fields: CommunityInvitationFields;
      name: string;
    }[];
    fields: { fields: CommunityInvitationFields; name: string }[];
    possessions: {
      fields: CommunityInvitationFields;
      invitationKey: string;
      name: string;
      possession: string;
    }[];
  };
  keys: Record<string, VectorKey>;
  proofs: {
    consent: string;
    consentContent: string;
    fields: CommunityInvitationFields;
    invitationKey: string;
    joiner: string;
    name: string;
    possession: string;
    possessionContent: string;
    secret: string;
  }[];
};

const vectors = loadVectors<CommunityInvitationVectors>('community-invitation');
const [sample] = vectors.proofs;
const joinerKey = privateKeyOf(vectors.keys[sample.joiner]);
const invitationKey = CommunityInvitationKey.fromSecret(sample.secret);
const refused = new InvalidCommunityInvitationError();

describe('community invitation proofs', () => {
  it.each(vectors.proofs)('reproduces the proofs where $name', (proof) => {
    const key = CommunityInvitationKey.fromSecret(proof.secret);
    const joiner = privateKeyOf(vectors.keys[proof.joiner]);

    expect(key.publicKey()).toBe(proof.invitationKey);
    expect(CommunityInvitationPossession.contentOf(proof.fields)).toBe(
      proof.possessionContent,
    );
    expect(CommunityInvitationConsent.contentOf(proof.fields)).toBe(
      proof.consentContent,
    );
    expect(CommunityInvitationPossession.sign(proof.fields, key)).toBe(
      proof.possession,
    );
    expect(CommunityInvitationConsent.sign(proof.fields, joiner)).toBe(
      proof.consent,
    );
    expect(() =>
      CommunityInvitationPossession.verify(
        proof.fields,
        proof.possession,
        proof.invitationKey,
      ),
    ).not.toThrow();
    expect(() =>
      CommunityInvitationConsent.verify(proof.fields, proof.consent),
    ).not.toThrow();
  });

  it('signs only the four fields, whatever order they come in', () => {
    const { networkId, invitationId, identityId, communityId } = sample.fields;

    expect(
      CommunityInvitationConsent.contentOf({
        networkId,
        invitationId,
        identityId,
        communityId,
      }),
    ).toBe(sample.consentContent);
  });

  it('accepts a network id in upper case and binds its exact text', () => {
    const fields = {
      ...sample.fields,
      networkId: sample.fields.networkId.toUpperCase(),
    };
    const possession = CommunityInvitationPossession.sign(
      fields,
      invitationKey,
    );

    expect(() =>
      CommunityInvitationPossession.verify(
        fields,
        possession,
        sample.invitationKey,
      ),
    ).not.toThrow();
    expect(() =>
      CommunityInvitationPossession.verify(
        sample.fields,
        possession,
        sample.invitationKey,
      ),
    ).toThrow(refused);
  });

  describe.each(vectors.invalid.fields)('with $name', ({ fields }) => {
    it('refuses to build or sign either preimage', () => {
      expect(() => CommunityInvitationPossession.contentOf(fields)).toThrow(
        refused,
      );
      expect(() => CommunityInvitationConsent.contentOf(fields)).toThrow(
        refused,
      );
      expect(() =>
        CommunityInvitationPossession.sign(fields, invitationKey),
      ).toThrow(refused);
      expect(() => CommunityInvitationConsent.sign(fields, joinerKey)).toThrow(
        refused,
      );
    });

    it('refuses to verify either proof', () => {
      expect(() =>
        CommunityInvitationPossession.verify(
          fields,
          sample.possession,
          sample.invitationKey,
        ),
      ).toThrow(refused);
      expect(() =>
        CommunityInvitationConsent.verify(fields, sample.consent),
      ).toThrow(refused);
    });
  });

  it.each([null, [], 'fields', new Map()])('refuses %p as fields', (fields) => {
    expect(() =>
      CommunityInvitationPossession.contentOf(
        fields as unknown as CommunityInvitationFields,
      ),
    ).toThrow(refused);
  });

  it.each(vectors.invalid.possessions)(
    'refuses $name',
    ({ fields, invitationKey: key, possession }) => {
      expect(() =>
        CommunityInvitationPossession.verify(fields, possession, key),
      ).toThrow(refused);
    },
  );

  it.each(vectors.invalid.consents)('refuses $name', ({ fields, consent }) => {
    expect(() => CommunityInvitationConsent.verify(fields, consent)).toThrow(
      refused,
    );
  });

  it('refuses a possession checked against a malformed invitation key', () => {
    expect(() =>
      CommunityInvitationPossession.verify(
        sample.fields,
        sample.possession,
        `${sample.invitationKey}=`,
      ),
    ).toThrow(refused);
  });

  it('signs possession only with an invitation key', () => {
    expect(() =>
      CommunityInvitationPossession.sign(
        sample.fields,
        joinerKey as unknown as CommunityInvitationKey,
      ),
    ).toThrow(refused);
  });

  it('signs consent only with the key of the joiner', () => {
    expect(() =>
      CommunityInvitationConsent.sign(
        sample.fields,
        privateKeyOf(vectors.keys.other),
      ),
    ).toThrow(refused);
    expect(() =>
      CommunityInvitationConsent.sign(
        sample.fields,
        'key' as unknown as PrivateKey,
      ),
    ).toThrow(refused);
  });
});
