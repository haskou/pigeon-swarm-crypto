import { CallMediaFramePeer } from './CallMediaFramePeer';

export interface CallMediaFrameSealerContext extends CallMediaFramePeer {
  epoch: number;
}
