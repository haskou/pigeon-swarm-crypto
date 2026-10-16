import type { PublicMutationAuthor } from './PublicMutationAuthor';

/** The signed fields of one public record mutation. */
export type PublicMutationBody = Readonly<{
  author: PublicMutationAuthor;
  frontier?: readonly string[];
  kind: 'put' | 'delete';
  operationId: string;
  payloadDigest: string;
  predecessor: string | null;
  recordId: string;
  sequence: number;
  store: string;
  version: 2;
}>;
