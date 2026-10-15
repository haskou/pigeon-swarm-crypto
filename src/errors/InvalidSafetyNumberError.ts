export class InvalidSafetyNumberError extends Error {
  constructor() {
    super('Invalid safety number input');
    this.name = 'InvalidSafetyNumberError';
  }
}
