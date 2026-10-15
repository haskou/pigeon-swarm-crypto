import {
  CommunityInviteReference,
  InvalidCommunityInviteReferenceError,
} from '../../src';
import { loadVectors } from '../vectors';

const { inviteToken } = loadVectors<{
  inviteToken: { reference: string; token: string };
}>('community-operation');

describe('CommunityInviteReference', () => {
  it('reproduces the vector reference', () => {
    expect(CommunityInviteReference.of(inviteToken.token)).toBe(
      inviteToken.reference,
    );
  });

  it.each([
    ['a padded token', `${inviteToken.token}=`],
    ['a short token', inviteToken.token.slice(0, 42)],
    ['a standard base64 token', `+${inviteToken.token.slice(1)}`],
    ['an empty token', ''],
  ])('rejects %s', (_name, token) => {
    expect(() => CommunityInviteReference.of(token)).toThrow(
      new InvalidCommunityInviteReferenceError(),
    );
  });
});
