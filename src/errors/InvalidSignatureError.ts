import { DomainError } from '@haskou/value-objects';

export class InvalidSignatureError extends DomainError {
  constructor(length: number) {
    super(`Signature must be a ${length}-character string`);
  }
}
