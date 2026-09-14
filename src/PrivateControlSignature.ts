import { ed25519 } from '@noble/curves/ed25519.js';
import { Buffer } from 'buffer';

import { InvalidPrivateControlError } from './errors/InvalidPrivateControlError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { PrivateControlEncoding } from './internal/PrivateControlEncoding';
import { PrivateControlRecord } from './internal/PrivateControlRecord';
import { StrictCanonicalJson } from './internal/StrictCanonicalJson';

export class PrivateControlSignature {
  private static checkSignatures(
    value: Record<string, unknown>,
    previousPolicy: Record<string, unknown>,
  ): void {
    const { signatures, ...unsigned } = value;
    const entries = Object.entries(PrivateControlRecord.object(signatures));
    const authorities = previousPolicy.authorityKeys as string[];

    if (
      entries.length < (previousPolicy.threshold as number) ||
      entries.length > authorities.length ||
      !Object.hasOwn(
        signatures as object,
        previousPolicy.sequencerKey as string,
      )
    )
      throw new InvalidPrivateControlError();
    const bytes = Buffer.from(
      'pigeon.private-control.v1\0' + StrictCanonicalJson.serialize(unsigned),
      'utf8',
    );
    for (const [key, signature] of entries) {
      if (
        !authorities.includes(key) ||
        !ed25519.verify(
          CanonicalBase64Url.decode(signature, 64),
          bytes,
          CanonicalBase64Url.decode(key, 32),
          { zip215: false },
        )
      )
        throw new InvalidPrivateControlError();
    }
  }

  public static authenticate(
    signedJson: string,
    trustedCheckpointJson: string,
    expectedMlsMessageHash: string,
  ): string {
    try {
      const value = StrictCanonicalJson.parse(signedJson);
      const previous = StrictCanonicalJson.parse(trustedCheckpointJson);
      const policy = PrivateControlEncoding.validate(
        value,
        previous,
        expectedMlsMessageHash,
      );
      this.checkSignatures(value, policy);

      return StrictCanonicalJson.serialize(value);
    } catch {
      throw new InvalidPrivateControlError();
    }
  }

  public static verify(
    signedJson: string,
    trustedCheckpointJson: string,
    expectedMlsMessageHash: string,
    expectedMlsContextHash: string,
  ): string {
    const canonical = this.authenticate(
      signedJson,
      trustedCheckpointJson,
      expectedMlsMessageHash,
    );
    const value = StrictCanonicalJson.parse(canonical);

    if (value.mlsContextHash !== expectedMlsContextHash)
      throw new InvalidPrivateControlError();

    return canonical;
  }
}
