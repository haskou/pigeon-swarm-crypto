export class InvalidPrivateOperationError extends Error {
  constructor() {
    super('Invalid private operation');
    this.name = 'InvalidPrivateOperationError';
  }
}
