export class InvalidMailboxRecordAuthorshipError extends Error {
  constructor() {
    super('Invalid mailbox record authorship input');
    this.name = 'InvalidMailboxRecordAuthorshipError';
  }
}
