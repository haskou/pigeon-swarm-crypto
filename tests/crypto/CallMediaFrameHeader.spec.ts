import { InvalidCallMediaFrameError } from '../../src';
import { CallMediaFrameHeader } from '../../src/internal/CallMediaFrameHeader';
import vectors from '../../vectors/call-media-frame.json';

const sealerId = Buffer.from(vectors.sealerId, 'base64url');

describe('CallMediaFrameHeader', () => {
  it('encodes the epoch, sealer id and sequence after the marker', () => {
    const { frame } = vectors.maxSequenceFrame;

    expect(
      Buffer.from(
        new CallMediaFrameHeader(
          vectors.epoch,
          sealerId,
          Number.MAX_SAFE_INTEGER,
        ).bytes(),
      ),
    ).toEqual(Buffer.from(frame, 'base64url').subarray(0, 25));
  });

  it.each([
    ['a sequence past 2^53 - 1', vectors.epoch, sealerId, 2 ** 53],
    ['a negative sequence', vectors.epoch, sealerId, -1],
    ['a short sealer id', vectors.epoch, sealerId.subarray(1), 0],
    ['a non-byte sealer id', vectors.epoch, 'sealer', 0],
    ['an epoch past 32 bits', 2 ** 32, sealerId, 0],
  ])('refuses %s', (_, epoch, id, sequence) => {
    expect(
      () => new CallMediaFrameHeader(epoch, id as Uint8Array, sequence),
    ).toThrow(InvalidCallMediaFrameError);
  });
});
