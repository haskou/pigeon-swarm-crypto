export class InvalidPrivateNetworkKeyError extends Error {
  constructor() {
    super('Invalid private network key');
    this.name = 'InvalidPrivateNetworkKeyError';
  }
}
