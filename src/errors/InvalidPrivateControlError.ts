export class InvalidPrivateControlError extends Error {
  constructor() {
    super('Invalid private control');
    this.name = 'InvalidPrivateControlError';
  }
}
