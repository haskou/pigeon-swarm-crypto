export class InvalidCommunityOperationSignatureError extends Error {
  constructor() {
    super('Invalid community operation signature');
    this.name = 'InvalidCommunityOperationSignatureError';
  }
}
