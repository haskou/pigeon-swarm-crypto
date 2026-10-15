export class InvalidDeviceRootRowError extends Error {
  constructor() {
    super('Invalid device root row input');
    this.name = 'InvalidDeviceRootRowError';
  }
}
