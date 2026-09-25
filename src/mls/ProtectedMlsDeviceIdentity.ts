import { UserRootKey } from '../UserRootKey';
import { RootProtectedEnvelope } from './internal/RootProtectedEnvelope';

export class ProtectedMlsDeviceIdentity {
  private static readonly DOMAIN = 'pigeon.mls-device-identity-protection.v1';
  private static readonly MAX_BYTES = 4096;

  public static protect(
    state: Uint8Array,
    rootKey: UserRootKey,
  ): ProtectedMlsDeviceIdentity {
    return new ProtectedMlsDeviceIdentity(
      RootProtectedEnvelope.protect(
        state,
        rootKey,
        this.DOMAIN,
        this.MAX_BYTES,
      ),
    );
  }

  constructor(private readonly serialized: string) {
    RootProtectedEnvelope.validate(
      serialized,
      ProtectedMlsDeviceIdentity.MAX_BYTES,
    );
  }

  public valueOf(): string {
    return this.serialized;
  }

  public unlock(rootKey: UserRootKey): Uint8Array {
    return RootProtectedEnvelope.unlock(
      this.serialized,
      rootKey,
      ProtectedMlsDeviceIdentity.DOMAIN,
      ProtectedMlsDeviceIdentity.MAX_BYTES,
    );
  }
}
