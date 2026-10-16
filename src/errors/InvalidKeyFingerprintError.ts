export class InvalidKeyFingerprintError extends Error {
  constructor() {
    super('Invalid key fingerprint input');
    this.name = 'InvalidKeyFingerprintError';
  }
}
