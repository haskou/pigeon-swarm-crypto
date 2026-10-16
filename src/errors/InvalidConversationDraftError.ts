export class InvalidConversationDraftError extends Error {
  constructor() {
    super('Invalid conversation draft');
    this.name = 'InvalidConversationDraftError';
  }
}
