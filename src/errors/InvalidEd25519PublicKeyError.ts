import { DomainError } from '@haskou/value-objects';

export class InvalidEd25519PublicKeyError extends DomainError {
  constructor() {
    super('Invalid Ed25519 public key PEM');
  }
}
