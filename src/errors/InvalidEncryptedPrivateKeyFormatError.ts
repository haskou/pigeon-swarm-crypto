import { DomainError } from '@haskou/value-objects';

export class InvalidEncryptedPrivateKeyFormatError extends DomainError {
  constructor(reason = 'Invalid encrypted private key format') {
    super(reason);
  }
}
