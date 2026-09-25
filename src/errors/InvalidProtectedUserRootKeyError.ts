import { DomainError } from '@haskou/value-objects';

export class InvalidProtectedUserRootKeyError extends DomainError {
  constructor() {
    super('Invalid protected user root key');
  }
}
