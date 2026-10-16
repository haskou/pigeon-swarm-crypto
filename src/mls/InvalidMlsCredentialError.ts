export class InvalidMlsCredentialError extends Error {
  constructor() {
    super('Invalid MLS credential');
    this.name = 'InvalidMlsCredentialError';
  }
}
