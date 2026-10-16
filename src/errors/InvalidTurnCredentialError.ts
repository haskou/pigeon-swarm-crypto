export class InvalidTurnCredentialError extends Error {
  constructor() {
    super('Invalid TURN credential');
    this.name = 'InvalidTurnCredentialError';
  }
}
