import { PrivateDeliveryBucketBytes } from './PrivateDeliveryBucketBytes';

export interface PrivateDeliveryHeader {
  readonly bucketBytes: PrivateDeliveryBucketBytes;
  readonly deliveryId: string;
  readonly expiresAt: number;
  readonly mailboxId: string;
  readonly version: 1;
}
