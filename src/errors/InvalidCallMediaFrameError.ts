export class InvalidCallMediaFrameError extends Error {
  constructor() {
    super('Invalid call media frame');
    this.name = 'InvalidCallMediaFrameError';
  }
}
