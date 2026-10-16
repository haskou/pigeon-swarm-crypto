export class InvalidPrivateNetworkRelayRecordError extends Error {
  constructor() {
    super('Invalid private network relay record');
    this.name = 'InvalidPrivateNetworkRelayRecordError';
  }
}
