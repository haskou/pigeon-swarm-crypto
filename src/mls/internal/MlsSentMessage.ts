import type { PrivateMessage } from 'ts-mls';

import type { MlsLeafOwner } from '../MlsLeafOwner';

/** A private message and the leaf that sent it. */
export interface MlsSentMessage {
  readonly message: PrivateMessage;
  readonly owner: MlsLeafOwner;
}
