export class InvalidDeviceSealedSecretError extends Error {
  constructor() {
    super('Invalid device sealed secret');
    this.name = 'InvalidDeviceSealedSecretError';
  }
}
