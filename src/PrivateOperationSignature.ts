import { ed25519 } from '@noble/curves/ed25519.js';
import { Buffer } from 'buffer';

import { InvalidPrivateOperationError } from './errors/InvalidPrivateOperationError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { PrivateOperationEncoding } from './internal/PrivateOperationEncoding';
import { StrictCanonicalJson } from './internal/StrictCanonicalJson';
import { PrivateKey } from './PrivateKey';

export class PrivateOperationSignature {
  private static signingBytes(value: Record<string, unknown>): Uint8Array {
    return Buffer.from(
      'pigeon.private-operation.v1\0' + StrictCanonicalJson.serialize(value),
      'utf8',
    );
  }

  public static sign(unsignedJson: string, key: PrivateKey): string {
    try {
      const value = StrictCanonicalJson.parse(unsignedJson);
      PrivateOperationEncoding.validate(value, false);
      const seed = CryptoAdapter.privateKeyToSeed(key.valueOf());

      if (
        value.authorDeviceKey !==
        CanonicalBase64Url.encode(ed25519.getPublicKey(seed))
      )
        throw new InvalidPrivateOperationError();
      const signature = CanonicalBase64Url.encode(
        ed25519.sign(this.signingBytes(value), seed),
      );
      const signed = StrictCanonicalJson.serialize({ ...value, signature });
      StrictCanonicalJson.parse(signed);

      return signed;
    } catch {
      throw new InvalidPrivateOperationError();
    }
  }

  public static verify(
    signedJson: string,
    expectedAuthorDeviceKey: string,
  ): string {
    try {
      const value = StrictCanonicalJson.parse(signedJson);
      PrivateOperationEncoding.validate(value, true);
      const publicKey = CanonicalBase64Url.decode(expectedAuthorDeviceKey, 32);

      if (value.authorDeviceKey !== expectedAuthorDeviceKey)
        throw new InvalidPrivateOperationError();
      const { signature, ...unsigned } = value;

      if (
        !ed25519.verify(
          CanonicalBase64Url.decode(signature, 64),
          this.signingBytes(unsigned),
          publicKey,
          { zip215: false },
        )
      )
        throw new InvalidPrivateOperationError();

      return StrictCanonicalJson.serialize(value);
    } catch {
      throw new InvalidPrivateOperationError();
    }
  }
}
