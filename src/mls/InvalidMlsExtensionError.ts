export class InvalidMlsExtensionError extends Error {
  constructor() {
    super('Invalid MLS extension');
    this.name = 'InvalidMlsExtensionError';
  }
}
