import type { StringValueObject } from '@haskou/value-objects';
import type { Buffer } from 'buffer';

export type SymmetricKeyDerivationOptions = {
  N?: number;
  p?: number;
  r?: number;
  salt: string | StringValueObject | Buffer;
};
