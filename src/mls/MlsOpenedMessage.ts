import type { MlsLeafOwner } from './MlsLeafOwner';

/** An application message an `MlsGroup` opened, with its verified sender. */
export interface MlsOpenedMessage {
  readonly plaintext: Uint8Array;
  readonly sender: MlsLeafOwner;
}
