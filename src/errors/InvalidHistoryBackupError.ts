export class InvalidHistoryBackupError extends Error {
  constructor() {
    super('Invalid history backup');
    this.name = 'InvalidHistoryBackupError';
  }
}
