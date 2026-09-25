import { PrivateDeliveryDescriptorData } from './PrivateDeliveryDescriptorData';

export interface PrivateDeliveryScheduleState {
  readonly entries: Array<{
    readonly descriptor: PrivateDeliveryDescriptorData;
    readonly privateKey: string;
  }>;
  readonly version: 1;
}
