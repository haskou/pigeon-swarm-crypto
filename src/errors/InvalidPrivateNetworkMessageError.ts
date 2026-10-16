export class InvalidPrivateNetworkMessageError extends Error {
  constructor() {
    super('Invalid private network message');
    this.name = 'InvalidPrivateNetworkMessageError';
  }
}
