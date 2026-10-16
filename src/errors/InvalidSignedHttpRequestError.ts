export class InvalidSignedHttpRequestError extends Error {
  constructor() {
    super('Invalid signed HTTP request');
    this.name = 'InvalidSignedHttpRequestError';
  }
}
