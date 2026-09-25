import { UserRootKey } from '../UserRootKey';
import { RootProtectedEnvelope } from './internal/RootProtectedEnvelope';

export class ProtectedMlsGroupState {
  private static readonly DOMAIN = 'pigeon.mls-group-state-protection.v1';
  private static readonly MAX_STATE_BYTES = 8 * 1024 * 1024;

  public static protect(
    state: Uint8Array,
    rootKey: UserRootKey,
  ): ProtectedMlsGroupState {
    return new ProtectedMlsGroupState(
      RootProtectedEnvelope.protect(
        state,
        rootKey,
        this.DOMAIN,
        this.MAX_STATE_BYTES,
      ),
    );
  }

  constructor(private readonly serialized: string) {
    RootProtectedEnvelope.validate(
      serialized,
      ProtectedMlsGroupState.MAX_STATE_BYTES,
    );
  }

  public valueOf(): string {
    return this.serialized;
  }

  public unlock(rootKey: UserRootKey): Uint8Array {
    return RootProtectedEnvelope.unlock(
      this.serialized,
      rootKey,
      ProtectedMlsGroupState.DOMAIN,
      ProtectedMlsGroupState.MAX_STATE_BYTES,
    );
  }
}
