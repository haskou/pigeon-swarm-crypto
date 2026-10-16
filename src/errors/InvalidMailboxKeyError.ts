export class InvalidMailboxKeyError extends Error {
  constructor() {
    super('Invalid mailbox key input');
    this.name = 'InvalidMailboxKeyError';
  }
}
