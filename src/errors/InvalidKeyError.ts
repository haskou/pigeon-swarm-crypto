import { DomainError } from '@haskou/value-objects';

export class InvalidKeyError extends DomainError {
  constructor(keySize: number, possibleKeySizes: number[]) {
    super(
      `Invalid key size: ${keySize}. Supported key sizes are ${possibleKeySizes.join(
        ', ',
      )}`,
    );
  }
}
