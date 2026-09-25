export class InvalidMlsStateError extends Error {
  constructor() {
    super('Invalid MLS state');
    this.name = 'InvalidMlsStateError';
  }
}
