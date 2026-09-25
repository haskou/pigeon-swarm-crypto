import { UserRootKey } from '../UserRootKey';
import { RootProtectedEnvelope } from './internal/RootProtectedEnvelope';

const DOMAIN = 'pigeon.private-delivery-key-schedule.v1';
const MAX_BYTES = 32768;

export class ProtectedPrivateDeliveryKeySchedule {
  public static protect(
    state: Uint8Array,
    rootKey: UserRootKey,
  ): ProtectedPrivateDeliveryKeySchedule {
    return new ProtectedPrivateDeliveryKeySchedule(
      RootProtectedEnvelope.protect(state, rootKey, DOMAIN, MAX_BYTES),
    );
  }

  public constructor(private readonly serialized: string) {
    RootProtectedEnvelope.validate(serialized, MAX_BYTES);
  }

  public unlock(rootKey: UserRootKey): Uint8Array {
    return RootProtectedEnvelope.unlock(
      this.serialized,
      rootKey,
      DOMAIN,
      MAX_BYTES,
    );
  }

  public valueOf(): string {
    return this.serialized;
  }
}
