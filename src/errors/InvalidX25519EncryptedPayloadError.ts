import { DomainError } from '@haskou/value-objects';

export class InvalidX25519EncryptedPayloadError extends DomainError {
  constructor() {
    super('Invalid X25519 encrypted payload');
  }
}
