export class InvalidDevicePairingError extends Error {
  constructor() {
    super('Invalid device pairing');
    this.name = 'InvalidDevicePairingError';
  }
}
