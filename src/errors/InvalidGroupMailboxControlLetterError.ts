export class InvalidGroupMailboxControlLetterError extends Error {
  constructor() {
    super('Invalid group mailbox control letter');
    this.name = 'InvalidGroupMailboxControlLetterError';
  }
}
