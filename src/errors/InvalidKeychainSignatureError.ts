export class InvalidKeychainSignatureError extends Error {
  constructor() {
    super('Invalid keychain signature');
    this.name = 'InvalidKeychainSignatureError';
  }
}
