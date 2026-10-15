import { sha256 } from '@noble/hashes/sha2.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';

import { CommunityFrontier } from './CommunityFrontier';
import { InvalidCommitmentError } from './errors/InvalidCommitmentError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CommitmentInput } from './internal/CommitmentInput';
import { StrictCanonicalJson } from './internal/StrictCanonicalJson';

export class StateDigest {
  private static readonly maxDepth = 64;

  private static isRecord(value: unknown): value is Record<string, unknown> {
    return (
      typeof value === 'object' &&
      value !== null &&
      Object.getPrototypeOf(value) === Object.prototype
    );
  }

  private static jsonChildren(value: unknown): unknown[] {
    if (Array.isArray(value)) return value;

    if (this.isRecord(value))
      return Object.values(value).filter((item) => item !== undefined);

    if (
      value === null ||
      typeof value === 'string' ||
      typeof value === 'boolean' ||
      (typeof value === 'number' && Number.isFinite(value))
    )
      return [];

    throw new InvalidCommitmentError();
  }

  private static checkJson(value: unknown, depth: number): void {
    if (depth > this.maxDepth) throw new InvalidCommitmentError();
    for (const item of this.jsonChildren(value))
      this.checkJson(item, depth + 1);
  }

  private static frontier(entry: unknown): [string, string[]] {
    if (
      !this.isRecord(entry) ||
      Object.keys(entry).length !== 2 ||
      !Array.isArray(entry.frontier)
    )
      throw new InvalidCommitmentError();

    return [
      CommitmentInput.text(entry.communityId),
      entry.frontier.map((head) => CommitmentInput.text(head)).sort(),
    ];
  }

  public static of(value: Record<string, unknown>): string {
    if (!this.isRecord(value)) throw new InvalidCommitmentError();
    this.checkJson(value, 0);

    return CanonicalBase64Url.encode(
      sha256(utf8ToBytes(StrictCanonicalJson.serialize(value))),
    );
  }

  public static ofBytes(bytes: Uint8Array): string {
    if (!(bytes instanceof Uint8Array)) throw new InvalidCommitmentError();

    return CanonicalBase64Url.encode(sha256(bytes));
  }

  public static communityFrontiers(entries: CommunityFrontier[]): string {
    if (!Array.isArray(entries)) throw new InvalidCommitmentError();
    const frontiers = entries
      .map((entry) => this.frontier(entry))
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));

    if (
      frontiers.some(
        ([communityId], index) =>
          index > 0 && frontiers[index - 1][0] === communityId,
      )
    )
      throw new InvalidCommitmentError();

    return CanonicalBase64Url.encode(
      sha256(utf8ToBytes(JSON.stringify(frontiers))),
    );
  }
}
