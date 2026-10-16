import { type _SHA256, sha256 } from '@noble/hashes/sha2.js';

import { InvalidProofOfWorkError } from './errors/InvalidProofOfWorkError';
import { ProofOfWorkEncoding } from './internal/ProofOfWorkEncoding';

export class ProofOfWork {
  private static readonly MINT_MARGIN_BITS = 7;
  private static readonly MINT_YIELD_INTERVAL = 4096;

  public static readonly MAX_DIFFICULTY_BITS =
    ProofOfWorkEncoding.MAX_DIFFICULTY_BITS;

  public static readonly MAX_FIELD_LENGTH =
    ProofOfWorkEncoding.MAX_FIELD_LENGTH;

  public static readonly MAX_NETWORK_IDS = ProofOfWorkEncoding.MAX_NETWORK_IDS;
  public static readonly MAX_NONCE_LENGTH =
    ProofOfWorkEncoding.MAX_NONCE_LENGTH;

  public static readonly MIN_DIFFICULTY_BITS =
    ProofOfWorkEncoding.MIN_DIFFICULTY_BITS;

  private readonly challenge: _SHA256;

  private static attempts(difficultyBits: number): number {
    return 2 ** (difficultyBits + ProofOfWork.MINT_MARGIN_BITS);
  }

  public static identityAdmission(
    identityId: string,
    networkIds: readonly string[],
  ): ProofOfWork {
    return new ProofOfWork(
      ProofOfWorkEncoding.identityAdmission(identityId, networkIds),
    );
  }

  public static mailboxCreation(
    mailboxId: string,
    postTokenHash: string,
    readTokenHash: string,
  ): ProofOfWork {
    return new ProofOfWork(
      ProofOfWorkEncoding.mailboxCreation(
        mailboxId,
        postTokenHash,
        readTokenHash,
      ),
    );
  }

  private constructor(challenge: Uint8Array) {
    this.challenge = sha256.create().update(challenge);
  }

  private workBits(nonce: string): number {
    return ProofOfWorkEncoding.leadingZeroBits(
      this.challenge.clone().update(ProofOfWorkEncoding.nonce(nonce)).digest(),
    );
  }

  public async mint(difficultyBits: number): Promise<string> {
    ProofOfWorkEncoding.assertDifficulty(difficultyBits);
    const attempts = ProofOfWork.attempts(difficultyBits);

    for (let counter = 0; counter < attempts; counter += 1) {
      if (counter > 0 && counter % ProofOfWork.MINT_YIELD_INTERVAL === 0) {
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
      }
      const nonce = String(counter);

      if (this.workBits(nonce) >= difficultyBits) {
        return nonce;
      }
    }
    throw new InvalidProofOfWorkError();
  }

  public mintSync(
    difficultyBits: number,
    accepts: (nonce: string) => boolean = () => true,
  ): string {
    ProofOfWorkEncoding.assertDifficulty(difficultyBits);
    const attempts = ProofOfWork.attempts(difficultyBits);

    for (let counter = 0; counter < attempts; counter += 1) {
      const nonce = String(counter);

      if (this.workBits(nonce) >= difficultyBits && accepts(nonce)) {
        return nonce;
      }
    }
    throw new InvalidProofOfWorkError();
  }

  public verify(nonce: unknown, difficultyBits: number): boolean {
    ProofOfWorkEncoding.assertDifficulty(difficultyBits);

    return (
      ProofOfWorkEncoding.isNonce(nonce) &&
      this.workBits(nonce) >= difficultyBits
    );
  }
}
