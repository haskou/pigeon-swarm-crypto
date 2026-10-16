import {
  defaultCapabilities,
  defaultLifetime,
  encodeMlsMessage,
  generateKeyPackageWithKey,
} from 'ts-mls';

import type { MlsLeafOwner } from './MlsLeafOwner';
import type { MlsLeafSigner } from './MlsLeafSigner';
import type { MlsPrivateKeyPackage } from './MlsPrivateKeyPackage';

import {
  decodeMessage,
  keyPackageOwner,
  rejection,
} from './internal/MlsGroupRules';
import { getMlsCiphersuite } from './internal/MlsRuntime';
import { MlsLeafCredential } from './MlsLeafCredential';

/**
 * An MLS key package whose leaf credential the owning identity and device
 * both signed (`MlsLeafCredential`). Its capabilities list the private-use
 * GroupContext extensions it supports, so it can join a group carrying them.
 */
export class MlsKeyPackage {
  public static async generate(
    signer: Pick<MlsLeafSigner, 'owner' | 'sign'>,
    extensionTypes: readonly number[] = [],
  ): Promise<MlsKeyPackage> {
    const cs = await getMlsCiphersuite();
    const signatureKeys = await cs.signature.keygen();
    const capabilities = defaultCapabilities();
    const { privatePackage, publicPackage } = await generateKeyPackageWithKey(
      {
        credentialType: 'basic',
        identity: MlsLeafCredential.issue(signer, signatureKeys.publicKey),
      },
      {
        ...capabilities,
        extensions: [...capabilities.extensions, ...extensionTypes],
      },
      defaultLifetime,
      [],
      signatureKeys,
      cs,
    );

    return new MlsKeyPackage(
      signer.owner,
      encodeMlsMessage({
        keyPackage: publicPackage,
        version: 'mls10',
        wireformat: 'mls_key_package',
      }),
      privatePackage,
    );
  }

  /** A stored key package, once its credential verifies again. */
  public static restore(
    publicBytes: Uint8Array,
    privatePackage: MlsPrivateKeyPackage,
  ): MlsKeyPackage {
    return new MlsKeyPackage(
      MlsKeyPackage.ownerOf(publicBytes),
      publicBytes,
      privatePackage,
    );
  }

  /**
   * The identity and device a published key package belongs to, only when
   * both signed its leaf credential.
   */
  public static ownerOf(publicBytes: Uint8Array): MlsLeafOwner {
    try {
      return keyPackageOwner(
        decodeMessage(publicBytes, 'mls_key_package').keyPackage,
      );
    } catch (error) {
      throw rejection(error);
    }
  }

  private constructor(
    public readonly owner: MlsLeafOwner,
    /** The encoded `mls_key_package` message to publish. */
    public readonly publicBytes: Uint8Array,
    /** Private material. Must stay on the device. */
    public readonly privatePackage: MlsPrivateKeyPackage,
  ) {}
}
