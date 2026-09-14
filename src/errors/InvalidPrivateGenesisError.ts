export class InvalidPrivateGenesisError extends Error {
  constructor() {
    super('Invalid private genesis');
    this.name = 'InvalidPrivateGenesisError';
  }
}
