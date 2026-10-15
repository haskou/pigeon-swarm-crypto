export class InvalidBearerCapabilityError extends Error {
  constructor() {
    super('Invalid bearer capability');
    this.name = 'InvalidBearerCapabilityError';
  }
}
