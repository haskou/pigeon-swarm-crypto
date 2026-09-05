import type { Media, StringValueObject } from '@haskou/value-objects';
import type { Buffer } from 'buffer';

export type HashPayload = string | StringValueObject | Media | Buffer;
