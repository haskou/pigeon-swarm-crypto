export class InvalidPublicRelayRecordError extends Error {
  constructor() {
    super('Invalid public relay record');
    this.name = 'InvalidPublicRelayRecordError';
  }
}
