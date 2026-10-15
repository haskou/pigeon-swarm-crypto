export class InvalidDeviceUnlockFactorError extends Error {
  constructor() {
    super('Invalid device unlock factor input');
    this.name = 'InvalidDeviceUnlockFactorError';
  }
}
