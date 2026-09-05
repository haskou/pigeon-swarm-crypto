import type { Media, StringValueObject } from '@haskou/value-objects';
import type { Buffer } from 'buffer';

export type CryptoPayload = string | StringValueObject | Buffer | Media;
