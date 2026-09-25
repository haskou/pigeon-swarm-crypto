import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { KeyPackage, PrivateKeyPackage } from 'ts-mls';

import { UserRootKey } from '../UserRootKey';
import { BinarySecretCodec } from './internal/BinarySecretCodec';
import { DeliveryBase64Url } from './internal/DeliveryBase64Url';
import {
  clonePrivateKeyPackage,
  decodePublicKeyPackage,
  encodePublicKeyPackage,
} from './internal/MlsCodec';
import {
  MLS_JOIN_PACKAGE_USE,
  MlsJoinPackageOperation,
} from './internal/MlsJoinPackageUse';
import { getMlsCiphersuite } from './internal/MlsRuntime';
import { InvalidMlsStateError } from './InvalidMlsStateError';
import { MlsCredential } from './MlsCredential';
import { ProtectedMlsJoinPackage } from './ProtectedMlsJoinPackage';

const MAX_SERIALIZED_BYTES = 16384;
const PROOF = new TextEncoder().encode('pigeon.mls-join-package-proof.v1');
const equal = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length &&
  left.every((value, index) => value === right[index]);
const packageIdBytes = (publicPackage: KeyPackage): Uint8Array => {
  const bytes = encodePublicKeyPackage(publicPackage);

  try {
    return sha256(bytes);
  } finally {
    bytes.fill(0);
  }
};

export class MlsJoinPackage {
  #consumed = false;

  #inUse = false;

  readonly #privatePackage: PrivateKeyPackage;

  readonly #publicPackage: KeyPackage;

  public static fromGenerated(
    publicPackage: KeyPackage,
    privatePackage: PrivateKeyPackage,
  ): MlsJoinPackage {
    return new MlsJoinPackage(publicPackage, privatePackage);
  }

  public static publicPackageFromBytes(bytes: Uint8Array): KeyPackage {
    return decodePublicKeyPackage(bytes);
  }

  public static async restore(
    protectedPackage: ProtectedMlsJoinPackage,
    rootKey: UserRootKey,
    expectedPackageId: string,
  ): Promise<MlsJoinPackage> {
    const state = protectedPackage.unlock(rootKey);

    try {
      const [publicBytes, initPrivateKey, hpkePrivateKey, signaturePrivateKey] =
        BinarySecretCodec.decode(state, 4, MAX_SERIALIZED_BYTES);
      const publicPackage = decodePublicKeyPackage(publicBytes);
      const expectedPackageIdBytes = DeliveryBase64Url.decode(
        expectedPackageId,
        32,
      );
      const restoredPackageIdBytes = packageIdBytes(publicPackage);

      try {
        if (!equal(expectedPackageIdBytes, restoredPackageIdBytes)) {
          throw new InvalidMlsStateError();
        }
      } finally {
        expectedPackageIdBytes.fill(0);
        restoredPackageIdBytes.fill(0);
      }
      const suite = await getMlsCiphersuite();
      const initPublicKey = x25519.getPublicKey(initPrivateKey);
      const leafPublicKey = x25519.getPublicKey(hpkePrivateKey);
      const signature = await suite.signature.sign(signaturePrivateKey, PROOF);

      try {
        if (
          !equal(initPublicKey, publicPackage.initKey) ||
          !equal(leafPublicKey, publicPackage.leafNode.hpkePublicKey) ||
          !(await suite.signature.verify(
            publicPackage.leafNode.signaturePublicKey,
            PROOF,
            signature,
          ))
        ) {
          throw new InvalidMlsStateError();
        }

        const restored = new MlsJoinPackage(publicPackage, {
          hpkePrivateKey,
          initPrivateKey,
          signaturePrivateKey,
        });
        state.fill(0);

        return restored;
      } finally {
        initPublicKey.fill(0);
        leafPublicKey.fill(0);
        signature.fill(0);
      }
    } catch {
      state.fill(0);
      throw new InvalidMlsStateError();
    }
  }

  private constructor(
    publicPackage: KeyPackage,
    privatePackage: PrivateKeyPackage,
  ) {
    this.#publicPackage = publicPackage;
    this.#privatePackage = privatePackage;
  }

  public get publicBytes(): Uint8Array {
    return encodePublicKeyPackage(this.#publicPackage);
  }

  public get packageId(): string {
    const value = packageIdBytes(this.#publicPackage);

    try {
      return DeliveryBase64Url.encode(value);
    } finally {
      value.fill(0);
    }
  }

  public get initPublicKey(): Uint8Array {
    return new Uint8Array(this.#publicPackage.initKey);
  }

  public get leafPublicKey(): Uint8Array {
    return new Uint8Array(this.#publicPackage.leafNode.hpkePublicKey);
  }

  public credential(): MlsCredential {
    const credential = this.#publicPackage.leafNode.credential;

    if (credential.credentialType !== 'basic') {
      throw new InvalidMlsStateError();
    }

    return {
      identity: new Uint8Array(credential.identity),
      signaturePublicKey: new Uint8Array(
        this.#publicPackage.leafNode.signaturePublicKey,
      ),
    };
  }

  public copyPublicPackage(): KeyPackage {
    return decodePublicKeyPackage(this.publicBytes);
  }

  public consumePrivatePackage(): PrivateKeyPackage {
    if (this.#consumed || this.#inUse) throw new InvalidMlsStateError();
    const privatePackage = clonePrivateKeyPackage(this.#privatePackage);
    this.destroy();

    return privatePackage;
  }

  public async [MLS_JOIN_PACKAGE_USE]<T>(
    operation: MlsJoinPackageOperation<T>,
  ): Promise<T> {
    if (this.#consumed || this.#inUse) throw new InvalidMlsStateError();
    const publicPackage = this.copyPublicPackage();
    const privatePackage = clonePrivateKeyPackage(this.#privatePackage);
    this.#inUse = true;

    try {
      const result = await operation(publicPackage, privatePackage);
      this.destroy();
      this.#inUse = false;

      return result;
    } catch (error) {
      privatePackage.initPrivateKey.fill(0);
      privatePackage.hpkePrivateKey.fill(0);
      privatePackage.signaturePrivateKey.fill(0);
      this.#inUse = false;
      throw error;
    }
  }

  public protect(rootKey: UserRootKey): ProtectedMlsJoinPackage {
    if (this.#consumed || this.#inUse) throw new InvalidMlsStateError();
    const state = BinarySecretCodec.encode(
      [
        this.publicBytes,
        this.#privatePackage.initPrivateKey,
        this.#privatePackage.hpkePrivateKey,
        this.#privatePackage.signaturePrivateKey,
      ],
      MAX_SERIALIZED_BYTES,
    );

    try {
      return ProtectedMlsJoinPackage.protect(state, rootKey);
    } finally {
      state.fill(0);
    }
  }

  public destroy(): void {
    this.#privatePackage.initPrivateKey.fill(0);
    this.#privatePackage.hpkePrivateKey.fill(0);
    this.#privatePackage.signaturePrivateKey.fill(0);
    this.#consumed = true;
  }
}
