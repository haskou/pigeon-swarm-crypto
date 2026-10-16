export class InvalidPrivateFreshnessRequestError extends Error {
  constructor() {
    super('Invalid private freshness request');
    this.name = 'InvalidPrivateFreshnessRequestError';
  }
}
