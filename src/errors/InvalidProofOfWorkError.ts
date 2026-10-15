export class InvalidProofOfWorkError extends Error {
  public constructor() {
    super('Invalid proof of work');
    this.name = 'InvalidProofOfWorkError';
  }
}
