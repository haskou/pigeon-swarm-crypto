import { CallMediaReplayWindow } from './CallMediaReplayWindow';
import { CallMediaSealerKey } from './CallMediaSealerKey';

export interface CallMediaSealer {
  key: CallMediaSealerKey;
  window: CallMediaReplayWindow;
}
