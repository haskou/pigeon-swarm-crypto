import {
  CallMediaFrameCipher,
  InvalidCallMediaFrameError,
  SymmetricKey,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import vectors from '../../vectors/call-media-frame.json';

const bytes = (value: string): Buffer => Buffer.from(value, 'base64url');

describe('CallMediaFrameCipher', () => {
  const cipher = CallMediaFrameCipher.fromKey(
    SymmetricKey.fromBase64(vectors.key),
  );
  const frame = bytes(vectors.frames[1].frame);

  afterEach(() => jest.restoreAllMocks());

  it.each(vectors.frames)(
    'seals and opens a $plaintext.length character frame',
    ({ frame: sealed, nonce, plaintext }) => {
      jest.spyOn(CryptoAdapter, 'randomBytes').mockReturnValueOnce(bytes(nonce));

      expect(Buffer.from(cipher.seal(bytes(plaintext))).toString('base64url')).toBe(
        sealed,
      );
      expect(Buffer.from(cipher.open(bytes(sealed))).toString('base64url')).toBe(
        plaintext,
      );
      expect(CallMediaFrameCipher.hasMarker(bytes(sealed))).toBeTrue();
    },
  );

  it('detects the frame marker', () => {
    expect(CallMediaFrameCipher.hasMarker(frame.subarray(0, 4))).toBeFalse();
    expect(CallMediaFrameCipher.hasMarker(new Uint8Array(40))).toBeFalse();
    expect(CallMediaFrameCipher.hasMarker('PSCE1' as never)).toBeFalse();
  });

  it('seals the largest frame', () => {
    const plaintext = new Uint8Array(8 * 1024 * 1024).fill(3);

    expect(cipher.open(cipher.seal(plaintext))).toEqual(plaintext);
    expect(() => cipher.seal(new Uint8Array(8 * 1024 * 1024 + 1))).toThrow(
      new InvalidCallMediaFrameError(),
    );
  });

  it.each([
    ['another key', CallMediaFrameCipher.fromKey(SymmetricKey.generate()), frame],
    ['a frame without marker', cipher, frame.subarray(1)],
    ['a truncated frame', cipher, frame.subarray(0, 32)],
    [
      'a tampered frame',
      cipher,
      Buffer.concat([frame.subarray(0, -1), Buffer.from([(frame.at(-1)! + 1) % 256])]),
    ],
    [
      'an oversized frame',
      cipher,
      Buffer.concat([frame.subarray(0, 5), Buffer.alloc(8 * 1024 * 1024 + 29)]),
    ],
    ['a non-byte frame', cipher, 'frame'],
  ])('refuses to open %s', (_, frameCipher, value) => {
    expect(() =>
      (frameCipher as CallMediaFrameCipher).open(value as Uint8Array),
    ).toThrow(InvalidCallMediaFrameError);
  });

  it('refuses to seal non-byte frames', () => {
    expect(() => cipher.seal('frame' as never)).toThrow(
      InvalidCallMediaFrameError,
    );
  });

  it('refuses keys that are not symmetric keys', () => {
    expect(() =>
      CallMediaFrameCipher.fromKey(Buffer.alloc(32) as never),
    ).toThrow(InvalidCallMediaFrameError);
  });
});
