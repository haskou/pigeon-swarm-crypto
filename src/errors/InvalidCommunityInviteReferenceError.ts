export class InvalidCommunityInviteReferenceError extends Error {
  constructor() {
    super('Invalid community invite reference');
    this.name = 'InvalidCommunityInviteReferenceError';
  }
}
