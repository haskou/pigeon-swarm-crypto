export class InvalidCommunityInvitationError extends Error {
  constructor() {
    super('Invalid community invitation');
    this.name = 'InvalidCommunityInvitationError';
  }
}
