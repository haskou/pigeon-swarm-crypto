import { ed25519 } from '@noble/curves/ed25519.js';
import { Buffer } from 'buffer';

import { InvalidPrivateGenesisError } from './errors/InvalidPrivateGenesisError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { PrivateGenesisEncoding } from './internal/PrivateGenesisEncoding';
import { StrictCanonicalJson } from './internal/StrictCanonicalJson';
import { PrivateKey } from './PrivateKey';

export class PrivateGenesisSignature {
  private static signingBytes(value: Record<string, unknown>): Uint8Array {
    return Buffer.from(
      'pigeon.private-genesis.v1\0' + StrictCanonicalJson.serialize(value),
      'utf8',
    );
  }

  public static sign(unsignedJson: string, key: PrivateKey): string {
    try {
      const value = StrictCanonicalJson.parse(unsignedJson);
      const seed = CryptoAdapter.privateKeyToSeed(key.valueOf());
      const owner = CanonicalBase64Url.encode(ed25519.getPublicKey(seed));
      PrivateGenesisEncoding.validate(value, owner, false);
      const signature = CanonicalBase64Url.encode(
        ed25519.sign(this.signingBytes(value), seed),
      );

      return StrictCanonicalJson.serialize({
        ...value,
        signatures: { [owner]: signature },
      });
    } catch {
      throw new InvalidPrivateGenesisError();
    }
  }

  public static verify(
    signedJson: string,
    expectedOwnerDeviceKey: string,
    expectedScopeId: string,
    expectedMlsContextHash: string,
  ): string {
    try {
      const value = StrictCanonicalJson.parse(signedJson);
      PrivateGenesisEncoding.validate(value, expectedOwnerDeviceKey, true);

      if (
        value.scopeId !== expectedScopeId ||
        value.mlsContextHash !== expectedMlsContextHash
      )
        throw new InvalidPrivateGenesisError();
      const { signatures, ...unsigned } = value;
      const signature = (signatures as Record<string, string>)[
        expectedOwnerDeviceKey
      ];

      if (
        !ed25519.verify(
          CanonicalBase64Url.decode(signature, 64),
          this.signingBytes(unsigned),
          CanonicalBase64Url.decode(expectedOwnerDeviceKey, 32),
          { zip215: false },
        )
      )
        throw new InvalidPrivateGenesisError();

      return StrictCanonicalJson.serialize(value);
    } catch {
      throw new InvalidPrivateGenesisError();
    }
  }
}
