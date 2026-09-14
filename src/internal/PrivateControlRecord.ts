import { InvalidPrivateControlError } from '../errors/InvalidPrivateControlError';

export class PrivateControlRecord {
  public static object(value: unknown): Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new InvalidPrivateControlError();

    return value as Record<string, unknown>;
  }

  public static read(
    value: unknown,
    fields: string[],
  ): Record<string, unknown> {
    const record = this.object(value);

    if (
      Object.keys(record).length !== fields.length ||
      fields.some((field) => !Object.hasOwn(record, field))
    )
      throw new InvalidPrivateControlError();

    return record;
  }
}
