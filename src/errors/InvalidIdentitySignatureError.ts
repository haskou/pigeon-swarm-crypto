export class InvalidIdentitySignatureError extends Error {
  constructor() {
    super('Invalid identity signature');
    this.name = 'InvalidIdentitySignatureError';
  }
}
