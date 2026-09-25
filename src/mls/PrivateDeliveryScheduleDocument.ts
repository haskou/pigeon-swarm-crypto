import { PrivateDeliveryDescriptorData } from './PrivateDeliveryDescriptorData';

export interface PrivateDeliveryScheduleDocument {
  readonly descriptors: PrivateDeliveryDescriptorData[];
  readonly signature: string;
  readonly signerIdentity: string;
  readonly signerPublicKey: string;
  readonly version: 1;
}
