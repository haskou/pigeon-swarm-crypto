import type { StringValueObject } from '@haskou/value-objects';
import type { Buffer } from 'buffer';

export type SymmetricKeyCryptOptions = {
  aad?: string | StringValueObject | Buffer;
};
