import { CallMediaSealer } from './CallMediaSealer';

export interface CallMediaEpoch {
  callKey: Promise<CryptoKey>;
  sealers: Map<string, CallMediaSealer>;
}
