import {
  defaultCapabilities,
  defaultLifetime,
  generateKeyPackageWithKey,
} from 'ts-mls';

import { UserRootKey } from '../UserRootKey';
import { AuthenticatedPrivateDeliverySchedule } from './AuthenticatedPrivateDeliverySchedule';
import { BinarySecretCodec } from './internal/BinarySecretCodec';
import { getMlsCiphersuite } from './internal/MlsRuntime';
import { InvalidMlsStateError } from './InvalidMlsStateError';
import { MlsCredential } from './MlsCredential';
import { MlsJoinPackage } from './MlsJoinPackage';
import { PrivateDeliveryDescriptor } from './PrivateDeliveryDescriptor';
import { ProtectedMlsDeviceIdentity } from './ProtectedMlsDeviceIdentity';

const MAX_IDENTITY_BYTES = 1024;
const MAX_SERIALIZED_BYTES = 4096;
const PROOF = new TextEncoder().encode('pigeon.mls-device-identity-proof.v1');

export class MlsDeviceIdentity {
  #destroyed = false;

  readonly #identity: Uint8Array;

  readonly #signaturePrivateKey: Uint8Array;

  readonly #signaturePublicKey: Uint8Array;

  public static async generate(
    identity: Uint8Array,
  ): Promise<MlsDeviceIdentity> {
    if (
      !(identity instanceof Uint8Array) ||
      identity.length === 0 ||
      identity.length > MAX_IDENTITY_BYTES
    ) {
      throw new InvalidMlsStateError();
    }
    const suite = await getMlsCiphersuite();
    const pair = await suite.signature.keygen();

    return new MlsDeviceIdentity(
      new Uint8Array(identity),
      new Uint8Array(pair.publicKey),
      new Uint8Array(pair.signKey),
    );
  }

  public static async restore(
    protectedIdentity: ProtectedMlsDeviceIdentity,
    rootKey: UserRootKey,
  ): Promise<MlsDeviceIdentity> {
    const state = protectedIdentity.unlock(rootKey);

    try {
      const [identity, publicKey, privateKey] = BinarySecretCodec.decode(
        state,
        3,
        MAX_SERIALIZED_BYTES,
      );

      if (
        identity.length > MAX_IDENTITY_BYTES ||
        publicKey.length !== 32 ||
        privateKey.length !== 48
      ) {
        throw new InvalidMlsStateError();
      }
      const suite = await getMlsCiphersuite();
      const signature = await suite.signature.sign(privateKey, PROOF);

      try {
        if (!(await suite.signature.verify(publicKey, PROOF, signature))) {
          throw new InvalidMlsStateError();
        }

        return new MlsDeviceIdentity(identity, publicKey, privateKey);
      } finally {
        signature.fill(0);
      }
    } catch {
      throw new InvalidMlsStateError();
    } finally {
      state.fill(0);
    }
  }

  private constructor(
    identity: Uint8Array,
    signaturePublicKey: Uint8Array,
    signaturePrivateKey: Uint8Array,
  ) {
    this.#identity = identity;
    this.#signaturePublicKey = signaturePublicKey;
    this.#signaturePrivateKey = signaturePrivateKey;
  }

  public get credential(): MlsCredential {
    if (this.#destroyed) throw new InvalidMlsStateError();

    return {
      identity: new Uint8Array(this.#identity),
      signaturePublicKey: new Uint8Array(this.#signaturePublicKey),
    };
  }

  public async createJoinPackage(): Promise<MlsJoinPackage> {
    if (this.#destroyed) throw new InvalidMlsStateError();
    const suite = await getMlsCiphersuite();
    const generated = await generateKeyPackageWithKey(
      { credentialType: 'basic', identity: new Uint8Array(this.#identity) },
      defaultCapabilities(),
      defaultLifetime,
      [],
      {
        publicKey: new Uint8Array(this.#signaturePublicKey),
        signKey: new Uint8Array(this.#signaturePrivateKey),
      },
      suite,
    );

    return MlsJoinPackage.fromGenerated(
      generated.publicPackage,
      generated.privatePackage,
    );
  }

  public async authenticateDeliverySchedule(
    descriptors: readonly PrivateDeliveryDescriptor[],
  ): Promise<AuthenticatedPrivateDeliverySchedule> {
    if (this.#destroyed) throw new InvalidMlsStateError();

    return AuthenticatedPrivateDeliverySchedule.sign(
      descriptors,
      this.credential,
      this.#signaturePrivateKey,
    );
  }

  public protect(rootKey: UserRootKey): ProtectedMlsDeviceIdentity {
    if (this.#destroyed) throw new InvalidMlsStateError();
    const state = BinarySecretCodec.encode(
      [this.#identity, this.#signaturePublicKey, this.#signaturePrivateKey],
      MAX_SERIALIZED_BYTES,
    );

    try {
      return ProtectedMlsDeviceIdentity.protect(state, rootKey);
    } finally {
      state.fill(0);
    }
  }

  public destroy(): void {
    this.#identity.fill(0);
    this.#signaturePublicKey.fill(0);
    this.#signaturePrivateKey.fill(0);
    this.#destroyed = true;
  }
}
