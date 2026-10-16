export class InvalidDeviceAuthorizationTransitionError extends Error {
  constructor() {
    super('Invalid device authorization transition');
    this.name = 'InvalidDeviceAuthorizationTransitionError';
  }
}
