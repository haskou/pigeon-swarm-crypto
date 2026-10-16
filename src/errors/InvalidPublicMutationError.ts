export class InvalidPublicMutationError extends Error {
  constructor() {
    super('Invalid public mutation');
    this.name = 'InvalidPublicMutationError';
  }
}
