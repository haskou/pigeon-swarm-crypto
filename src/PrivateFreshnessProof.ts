import { ed25519 } from '@noble/curves/ed25519.js';
import { Buffer } from 'buffer';

import { InvalidPrivateFreshnessProofError } from './errors/InvalidPrivateFreshnessProofError';
import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { CryptoAdapter } from './internal/CryptoAdapter';
import { PrivateFreshnessEncoding } from './internal/PrivateFreshnessEncoding';
import { StrictCanonicalJson } from './internal/StrictCanonicalJson';
import { PrivateKey } from './PrivateKey';

export class PrivateFreshnessProof {
  private static matchesRequest(
    proof: Record<string, unknown>,
    request: Record<string, unknown>,
  ): boolean {
    return (
      proof.scopeId === request.scopeId &&
      proof.nonce === request.nonce &&
      proof.revision === request.expectedRevision &&
      proof.headHash === request.expectedHeadHash &&
      proof.batchCommitment === request.batchCommitment
    );
  }

  private static signingBytes(value: Record<string, unknown>): Uint8Array {
    return Buffer.from(
      'pigeon.private-freshness.v1\0' + StrictCanonicalJson.serialize(value),
      'utf8',
    );
  }

  public static sign(unsignedProofJson: string, key: PrivateKey): string {
    try {
      const value = StrictCanonicalJson.parse(unsignedProofJson);
      PrivateFreshnessEncoding.validateProof(value, false);
      const seed = CryptoAdapter.privateKeyToSeed(key.valueOf());

      if (
        value.signerKey !==
        CanonicalBase64Url.encode(ed25519.getPublicKey(seed))
      )
        throw new InvalidPrivateFreshnessProofError();
      const signature = CanonicalBase64Url.encode(
        ed25519.sign(this.signingBytes(value), seed),
      );
      const signed = StrictCanonicalJson.serialize({ ...value, signature });
      StrictCanonicalJson.parse(signed);

      return signed;
    } catch {
      throw new InvalidPrivateFreshnessProofError();
    }
  }

  public static verify(
    signedProofJson: string,
    expectedSignerKey: string,
    expectedRequestJson: string,
  ): string {
    try {
      const value = StrictCanonicalJson.parse(signedProofJson);
      const request = StrictCanonicalJson.parse(expectedRequestJson);
      PrivateFreshnessEncoding.validateProof(value, true);
      PrivateFreshnessEncoding.validateRequest(request);
      const publicKey = CanonicalBase64Url.decode(expectedSignerKey, 32);

      if (
        value.signerKey !== expectedSignerKey ||
        !this.matchesRequest(value, request)
      )
        throw new InvalidPrivateFreshnessProofError();
      const { signature, ...unsigned } = value;

      if (
        !ed25519.verify(
          CanonicalBase64Url.decode(signature, 64),
          this.signingBytes(unsigned),
          publicKey,
          { zip215: false },
        )
      )
        throw new InvalidPrivateFreshnessProofError();

      return StrictCanonicalJson.serialize(value);
    } catch {
      throw new InvalidPrivateFreshnessProofError();
    }
  }
}
