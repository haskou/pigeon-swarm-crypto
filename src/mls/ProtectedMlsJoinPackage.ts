import { UserRootKey } from '../UserRootKey';
import { RootProtectedEnvelope } from './internal/RootProtectedEnvelope';

export class ProtectedMlsJoinPackage {
  private static readonly DOMAIN = 'pigeon.mls-join-package-protection.v1';
  private static readonly MAX_BYTES = 16384;

  public static protect(
    state: Uint8Array,
    rootKey: UserRootKey,
  ): ProtectedMlsJoinPackage {
    return new ProtectedMlsJoinPackage(
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
      ProtectedMlsJoinPackage.MAX_BYTES,
    );
  }

  public valueOf(): string {
    return this.serialized;
  }

  public unlock(rootKey: UserRootKey): Uint8Array {
    return RootProtectedEnvelope.unlock(
      this.serialized,
      rootKey,
      ProtectedMlsJoinPackage.DOMAIN,
      ProtectedMlsJoinPackage.MAX_BYTES,
    );
  }
}
