export class InvalidRecoveryKeyError extends Error {
  constructor() {
    super('Invalid recovery key');
    this.name = 'InvalidRecoveryKeyError';
  }
}
