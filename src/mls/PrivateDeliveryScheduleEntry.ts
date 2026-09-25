import { PrivateDeliveryDescriptor } from './PrivateDeliveryDescriptor';

export interface PrivateDeliveryScheduleEntry {
  readonly descriptor: PrivateDeliveryDescriptor;
  readonly privateKey: Uint8Array;
}
