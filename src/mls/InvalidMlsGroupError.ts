/** An MLS group refused a message, commit, welcome or operation. */
export class InvalidMlsGroupError extends Error {
  constructor() {
    super('Invalid MLS group operation');
    this.name = 'InvalidMlsGroupError';
  }
}
