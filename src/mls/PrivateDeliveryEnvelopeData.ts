import { PrivateDeliveryHeader } from './PrivateDeliveryHeader';

export interface PrivateDeliveryEnvelopeData extends PrivateDeliveryHeader {
  readonly ciphertext: string;
}
