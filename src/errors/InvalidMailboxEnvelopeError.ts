export class InvalidMailboxEnvelopeError extends Error {
  constructor() {
    super('Invalid mailbox envelope');
    this.name = 'InvalidMailboxEnvelopeError';
  }
}
