import { DomainError } from '@haskou/value-objects';

export class InvalidX25519KeyError extends DomainError {
  constructor() {
    super('Invalid X25519 key');
  }
}
