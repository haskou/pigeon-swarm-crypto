import { createHash } from 'node:crypto';

import vectors from '../../vectors/proof-of-work.json';
import * as Crypto from '../../src';
import { ProofOfWorkEncoding } from '../../src/internal/ProofOfWorkEncoding';

type IdentityAdmissionChallenge = {
  identityId: string;
  networkIds: string[];
};
type MailboxCreationChallenge = {
  mailboxId: string;
  postTokenHash: string;
  readTokenHash: string;
};
type ProofOfWorkVector = {
  challenge: unknown;
  difficultyBits: number;
  digestHex?: string;
  leadingZeroBits?: number;
  minted?: boolean;
  name: string;
  nonce: unknown;
  preimageHex?: string;
};
type AcceptedProofOfWorkVector = ProofOfWorkVector & {
  digestHex: string;
  leadingZeroBits: number;
  nonce: string;
  preimageHex: string;
};
type ProofOfWorkFormatVectors = {
  accepted: AcceptedProofOfWorkVector[];
  domain: string;
  invalidChallenges: { challenge: unknown; name: string }[];
  rejected: ProofOfWorkVector[];
};

const { InvalidProofOfWorkError, ProofOfWork } = Crypto;

const leadingZeroBits = (digest: Buffer): number => {
  const firstNonZero = digest.findIndex((byte) => byte !== 0);

  return firstNonZero === -1
    ? digest.length * 8
    : firstNonZero * 8 + 8 - digest[firstNonZero].toString(2).length;
};

const identityAdmission = (
  challenge: IdentityAdmissionChallenge,
): Crypto.ProofOfWork =>
  ProofOfWork.identityAdmission(challenge.identityId, challenge.networkIds);
const mailboxCreation = (
  challenge: MailboxCreationChallenge,
): Crypto.ProofOfWork =>
  ProofOfWork.mailboxCreation(
    challenge.mailboxId,
    challenge.postTokenHash,
    challenge.readTokenHash,
  );

const identityPrefix = (challenge: IdentityAdmissionChallenge): Uint8Array =>
  ProofOfWorkEncoding.identityAdmission(
    challenge.identityId,
    challenge.networkIds,
  );
const mailboxPrefix = (challenge: MailboxCreationChallenge): Uint8Array =>
  ProofOfWorkEncoding.mailboxCreation(
    challenge.mailboxId,
    challenge.postTokenHash,
    challenge.readTokenHash,
  );

const expectInvalid = (action: () => unknown): void => {
  try {
    action();
  } catch (error) {
    expect(error).toBeInstanceOf(InvalidProofOfWorkError);
    expect((error as Error).message).toBe('Invalid proof of work');
    expect((error as Error).cause).toBeUndefined();

    return;
  }
  throw new Error('expected InvalidProofOfWorkError');
};

describe('ProofOfWork', () => {
  const formats = [
    {
      name: 'identity admission',
      vectors: vectors.identityAdmission as ProofOfWorkFormatVectors,
      challenge: (value: unknown) =>
        identityAdmission(value as IdentityAdmissionChallenge),
      prefix: (value: unknown) =>
        identityPrefix(value as IdentityAdmissionChallenge),
    },
    {
      name: 'mailbox creation',
      vectors: vectors.mailboxCreation as ProofOfWorkFormatVectors,
      challenge: (value: unknown) =>
        mailboxCreation(value as MailboxCreationChallenge),
      prefix: (value: unknown) =>
        mailboxPrefix(value as MailboxCreationChallenge),
    },
  ];

  it('exposes the documented limits', () => {
    expect(ProofOfWork.MIN_DIFFICULTY_BITS).toBe(
      vectors.limits.minDifficultyBits,
    );
    expect(ProofOfWork.MAX_DIFFICULTY_BITS).toBe(
      vectors.limits.maxDifficultyBits,
    );
    expect(ProofOfWork.MAX_NONCE_LENGTH).toBe(vectors.limits.maxNonceLength);
    expect(ProofOfWork.MAX_FIELD_LENGTH).toBe(vectors.limits.maxFieldLength);
    expect(ProofOfWork.MAX_NETWORK_IDS).toBe(vectors.limits.maxNetworkIds);
  });

  describe.each(formats)('$name', ({ challenge, prefix, vectors: format }) => {
    it('uses a versioned domain', () => {
      expect(format.domain).toMatch(/:v2$/);
    });

    it.each(format.accepted)(
      'pins the preimage and digest of $name',
      (vector) => {
        const preimage = Buffer.concat([
          prefix(vector.challenge),
          ProofOfWorkEncoding.nonce(vector.nonce),
        ]);
        const digest = createHash('sha256').update(preimage).digest();

        expect(preimage.toString('hex')).toBe(vector.preimageHex);
        expect(
          preimage.subarray(4, 4 + format.domain.length).toString('ascii'),
        ).toBe(format.domain);
        expect(digest.toString('hex')).toBe(vector.digestHex);
        expect(leadingZeroBits(digest)).toBe(vector.leadingZeroBits);
      },
    );

    it.each(format.accepted)(
      'accepts $name exactly up to its work',
      (vector) => {
        const proof = challenge(vector.challenge);

        expect(proof.verify(vector.nonce, vector.difficultyBits)).toBe(true);
        expect(proof.verify(vector.nonce, vector.leadingZeroBits)).toBe(true);
        expect(proof.verify(vector.nonce, vector.leadingZeroBits + 1)).toBe(
          false,
        );
      },
    );

    it.each(format.accepted.filter((vector) => vector.minted === true))(
      'mints $name synchronously and asynchronously',
      async (vector) => {
        const proof = challenge(vector.challenge);

        expect(proof.mintSync(vector.difficultyBits)).toBe(vector.nonce);
        await expect(proof.mint(vector.difficultyBits)).resolves.toBe(
          vector.nonce,
        );
      },
    );

    it.each(format.rejected)('rejects $name', (vector) => {
      const proof = challenge(vector.challenge);

      expect(proof.verify(vector.nonce, vector.difficultyBits)).toBe(false);
    });

    it.each(
      format.rejected.filter((vector) => vector.preimageHex !== undefined),
    )('pins the preimage and digest of rejected $name', (vector) => {
      const preimage = Buffer.concat([
        prefix(vector.challenge),
        ProofOfWorkEncoding.nonce(vector.nonce as string),
      ]);
      const digest = createHash('sha256').update(preimage).digest();

      expect(preimage.toString('hex')).toBe(vector.preimageHex);
      expect(digest.toString('hex')).toBe(vector.digestHex);
      expect(leadingZeroBits(digest)).toBe(vector.leadingZeroBits);
    });

    it.each(format.invalidChallenges)(
      'refuses the challenge with $name',
      (vector) => {
        expectInvalid(() => challenge(vector.challenge));
      },
    );

    it.each(vectors.invalidDifficulties)(
      'refuses difficulty %p',
      async (difficultyBits) => {
        const proof = challenge(format.accepted[0].challenge);
        const bits = difficultyBits as number;

        expectInvalid(() => proof.verify(format.accepted[0].nonce, bits));
        expectInvalid(() => proof.mintSync(bits));
        await expect(proof.mint(bits)).rejects.toBeInstanceOf(
          InvalidProofOfWorkError,
        );
      },
    );
  });

  it('separates the identity admission and mailbox creation domains', () => {
    const shared = 'a';
    const identityPreimage = identityPrefix({
      identityId: shared,
      networkIds: [shared],
    });
    const mailboxPreimage = mailboxPrefix({
      mailboxId: shared,
      postTokenHash: shared,
      readTokenHash: shared,
    });

    expect(Buffer.from(identityPreimage).toString('hex')).not.toBe(
      Buffer.from(mailboxPreimage).toString('hex'),
    );
  });

  it('sorts networks by their bytes', () => {
    expect(
      Buffer.from(
        identityPrefix({ identityId: 'id', networkIds: ['b', 'B', 'a'] }),
      ).toString('hex'),
    ).toBe(
      Buffer.from(
        identityPrefix({ identityId: 'id', networkIds: ['B', 'a', 'b'] }),
      ).toString('hex'),
    );
  });

  it('accepts fields and networks at their limits', () => {
    const field = '~'.repeat(ProofOfWork.MAX_FIELD_LENGTH);
    const networks = Array.from(
      { length: ProofOfWork.MAX_NETWORK_IDS },
      (_, index) => field.slice(0, -3) + String(index).padStart(3, '0'),
    );

    expect(ProofOfWork.identityAdmission(field, networks)).toBeInstanceOf(
      ProofOfWork,
    );
    expect(ProofOfWork.mailboxCreation(field, field, field)).toBeInstanceOf(
      ProofOfWork,
    );
  });

  it('accepts the longest canonical nonce shape', () => {
    const proof = identityAdmission(
      vectors.identityAdmission.accepted[0].challenge,
    );
    const longest = '9'.repeat(ProofOfWork.MAX_NONCE_LENGTH);

    expect(proof.verify(longest, ProofOfWork.MIN_DIFFICULTY_BITS)).toBe(
      leadingZeroBits(
        createHash('sha256')
          .update(
            Buffer.concat([
              identityPrefix(vectors.identityAdmission.accepted[0].challenge),
              ProofOfWorkEncoding.nonce(longest),
            ]),
          )
          .digest(),
      ) >= ProofOfWork.MIN_DIFFICULTY_BITS,
    );
    expect(proof.verify('0', ProofOfWork.MAX_DIFFICULTY_BITS)).toBe(false);
  });

  it('counts every zero bit of an all-zero digest', () => {
    expect(ProofOfWorkEncoding.leadingZeroBits(new Uint8Array(32))).toBe(256);
    expect(ProofOfWorkEncoding.leadingZeroBits(Uint8Array.of(0, 1, 0))).toBe(
      15,
    );
  });

  it('mints the first nonce the caller also accepts', () => {
    const vector = vectors.mailboxCreation.accepted[0];
    const proof = mailboxCreation(vector.challenge);
    const exact = proof.mintSync(
      4,
      (nonce) => proof.verify(nonce, 4) && !proof.verify(nonce, 5),
    );

    expect(proof.verify(exact, 4)).toBe(true);
    expect(proof.verify(exact, 5)).toBe(false);
    expect(proof.mintSync(vector.difficultyBits, () => true)).toBe(
      vector.nonce,
    );
  });

  it('fails closed when its bounded nonce search finds no proof', async () => {
    const proof = mailboxCreation(
      vectors.mailboxCreation.accepted[0].challenge,
    );
    const unbounded = 1_000_000;
    let offered = 0;
    let hashed = 0;

    expectInvalid(() =>
      proof.mintSync(ProofOfWork.MIN_DIFFICULTY_BITS, () => {
        offered += 1;
        if (offered > unbounded) throw new Error('Unbounded nonce search');

        return false;
      }),
    );
    expect(offered).toBeGreaterThan(0);

    const leadingZeroBits = jest
      .spyOn(ProofOfWorkEncoding, 'leadingZeroBits')
      .mockImplementation(() => {
        hashed += 1;
        if (hashed > unbounded) throw new Error('Unbounded nonce search');

        return 0;
      });

    try {
      await expect(
        proof.mint(ProofOfWork.MIN_DIFFICULTY_BITS),
      ).rejects.toBeInstanceOf(InvalidProofOfWorkError);
      expect(hashed).toBeGreaterThan(0);
    } finally {
      leadingZeroBits.mockRestore();
    }
  });

  it('yields to the event loop while minting asynchronously', async () => {
    const vector = vectors.mailboxCreation.accepted[1];
    const proof = mailboxCreation(vector.challenge);
    let ticked = false;
    setTimeout(() => {
      ticked = true;
    }, 0);

    await expect(proof.mint(vector.difficultyBits)).resolves.toBe(vector.nonce);
    expect(ticked).toBe(true);
  });

  it('does not echo input in errors', () => {
    const secret = 'secret value';

    expectInvalid(() => ProofOfWork.mailboxCreation(secret, secret, secret));
    expect(new InvalidProofOfWorkError().message).not.toContain(secret);
    expect(new InvalidProofOfWorkError().name).toBe('InvalidProofOfWorkError');
  });
});
