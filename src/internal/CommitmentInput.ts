import { InvalidCommitmentError } from '../errors/InvalidCommitmentError';

export class CommitmentInput {
  public static text(value: unknown): string {
    if (
      typeof value !== 'string' ||
      value === '' ||
      /[\uD800-\uDFFF]/u.test(value)
    )
      throw new InvalidCommitmentError();

    return value;
  }

  public static counter(value: unknown): number {
    if (!Number.isSafeInteger(value) || (value as number) < 0)
      throw new InvalidCommitmentError();

    return value as number;
  }
}
