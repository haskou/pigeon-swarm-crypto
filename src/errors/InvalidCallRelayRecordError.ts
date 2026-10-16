export class InvalidCallRelayRecordError extends Error {
  constructor() {
    super('Invalid call relay record');
    this.name = 'InvalidCallRelayRecordError';
  }
}
