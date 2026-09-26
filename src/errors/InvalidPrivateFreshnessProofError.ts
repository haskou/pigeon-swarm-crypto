export class InvalidPrivateFreshnessProofError extends Error {
  public constructor() {
    super('Invalid private freshness proof');
    this.name = 'InvalidPrivateFreshnessProofError';
  }
}
