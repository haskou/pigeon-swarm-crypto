export class InvalidCanonicalJsonError extends Error {
  constructor() {
    super('Invalid canonical JSON');
    this.name = 'InvalidCanonicalJsonError';
  }
}
