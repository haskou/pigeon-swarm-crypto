export class InvalidCommitmentError extends Error {
  constructor() {
    super('Invalid commitment');
    this.name = 'InvalidCommitmentError';
  }
}
