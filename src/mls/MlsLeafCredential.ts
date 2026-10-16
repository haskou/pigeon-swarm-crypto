import type { MlsLeafOwner } from './MlsLeafOwner';
import type { MlsLeafSigner } from './MlsLeafSigner';

import { StrictCanonicalJson } from '../internal/StrictCanonicalJson';
import { PublicKey } from '../PublicKey';
import { Signature } from '../Signature';
import { DeliveryBase64Url } from './internal/DeliveryBase64Url';
import { InvalidMlsCredentialError } from './InvalidMlsCredentialError';

/**
 * The basic-credential identity of an MLS leaf: identity, device and both of
 * their Ed25519 signatures over the leaf's MLS signature key, joined by NUL.
 */
export class MlsLeafCredential {
  private static readonly DOMAIN = 'pigeon:mls-leaf-credential:v2\n';
  private static readonly SEPARATOR = '\u0000';
  private static readonly MAX_BYTES = 1024;
  private static readonly IDENTITY_ID = /^[A-Za-z0-9+/]{59}=$/;
  private static readonly DEVICE_CREDENTIAL =
    /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/]{59}=\n-----END PUBLIC KEY-----\n$/;

  private static readonly decoder = new TextDecoder('utf-8', { fatal: true });

  private static message(
    { deviceCredential, identityId }: MlsLeafOwner,
    signaturePublicKey: Uint8Array,
  ): string {
    return (
      MlsLeafCredential.DOMAIN +
      StrictCanonicalJson.serialize({
        deviceCredential,
        identityId,
        signaturePublicKey: DeliveryBase64Url.encode(signaturePublicKey),
      })
    );
  }

  private static identityKey(identityId: string): PublicKey {
    return PublicKey.fromPEM(
      `-----BEGIN PUBLIC KEY-----\n${identityId}\n-----END PUBLIC KEY-----\n`,
    );
  }

  private static parts(identity: Uint8Array): {
    owner: MlsLeafOwner;
    signatures: [string, string];
  } {
    if (identity.length > MlsLeafCredential.MAX_BYTES)
      throw new InvalidMlsCredentialError();
    const parts = MlsLeafCredential.decoder
      .decode(identity)
      .split(MlsLeafCredential.SEPARATOR);
    const [identityId, deviceCredential, identitySignature, deviceSignature] =
      parts;

    if (
      parts.length !== 4 ||
      !MlsLeafCredential.IDENTITY_ID.test(identityId) ||
      !MlsLeafCredential.DEVICE_CREDENTIAL.test(deviceCredential)
    )
      throw new InvalidMlsCredentialError();

    return {
      owner: { deviceCredential, identityId },
      signatures: [identitySignature, deviceSignature],
    };
  }

  /** The credential identity bytes the signer vouches for. */
  public static issue(
    signer: Pick<MlsLeafSigner, 'owner' | 'sign'>,
    signaturePublicKey: Uint8Array,
  ): Uint8Array {
    const { deviceCredential, identityId } = signer.owner;
    const { device, identity } = signer.sign(
      MlsLeafCredential.message(signer.owner, signaturePublicKey),
    );

    return new TextEncoder().encode(
      [identityId, deviceCredential, identity, device].join(
        MlsLeafCredential.SEPARATOR,
      ),
    );
  }

  /** The owner the identity bytes name, without verifying their signatures. */
  public static ownerOf(identity: Uint8Array): MlsLeafOwner {
    try {
      return MlsLeafCredential.parts(identity).owner;
    } catch {
      throw new InvalidMlsCredentialError();
    }
  }

  /** The owner, once both signatures over the signature key verify. */
  public static verify(
    identity: Uint8Array,
    signaturePublicKey: Uint8Array,
  ): MlsLeafOwner {
    try {
      const {
        owner,
        signatures: [identitySignature, deviceSignature],
      } = MlsLeafCredential.parts(identity);
      const message = MlsLeafCredential.message(owner, signaturePublicKey);

      if (
        MlsLeafCredential.identityKey(owner.identityId).isValidSignature(
          message,
          new Signature(identitySignature),
        ) &&
        PublicKey.fromPEM(owner.deviceCredential).isValidSignature(
          message,
          new Signature(deviceSignature),
        )
      )
        return owner;
    } catch {
      // Any malformed part rejects the credential below.
    }
    throw new InvalidMlsCredentialError();
  }
}
