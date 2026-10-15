import type { PublicMutationBody } from './PublicMutationBody';

export type PublicMutation = PublicMutationBody &
  Readonly<{ signature: string }>;
