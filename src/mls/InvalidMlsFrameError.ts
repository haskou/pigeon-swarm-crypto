export class InvalidMlsFrameError extends Error {
  constructor() {
    super('Invalid MLS frame');
    this.name = 'InvalidMlsFrameError';
  }
}
