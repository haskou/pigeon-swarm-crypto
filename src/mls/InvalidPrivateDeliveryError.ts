export class InvalidPrivateDeliveryError extends Error {
  public constructor() {
    super('Invalid private delivery');
  }
}
