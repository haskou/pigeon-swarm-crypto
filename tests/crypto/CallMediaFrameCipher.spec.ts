import {
  CallMediaFrameCipher,
  InvalidCallMediaFrameError,
  SymmetricKey,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import vectors from '../../vectors/call-media-frame.json';

const bytes = (value: string): Buffer => Buffer.from(value, 'base64url');

describe('CallMediaFrameCipher', () => {
  const frame = bytes(vectors.frames[1].frame);
  let cipher: CallMediaFrameCipher;

  beforeAll(async () => {
    cipher = await CallMediaFrameCipher.fromKey(
      SymmetricKey.fromBase64(vectors.key),
    );
  });

  afterEach(() => jest.restoreAllMocks());

  it.each(vectors.frames)(
    'seals and opens a $plaintext.length character frame',
    async ({ frame: sealed, nonce, plaintext }) => {
      jest.spyOn(CryptoAdapter, 'randomBytes').mockReturnValueOnce(bytes(nonce));

      expect(
        Buffer.from(await cipher.seal(bytes(plaintext))).toString('base64url'),
      ).toBe(sealed);
      expect(
        Buffer.from(await cipher.open(bytes(sealed))).toString('base64url'),
      ).toBe(plaintext);
      expect(CallMediaFrameCipher.hasMarker(bytes(sealed))).toBeTrue();
    },
  );

  it('holds the call key only as a non-extractable AES-GCM CryptoKey', async () => {
    const importKey = jest.spyOn(globalThis.crypto.subtle, 'importKey');

    await CallMediaFrameCipher.fromKey(SymmetricKey.fromBase64(vectors.key));
    const [[, material, algorithm, extractable, usages]] = importKey.mock
      .calls as unknown as [[string, Uint8Array, string, boolean, string[]]];
    const key = await (importKey.mock.results[0].value as Promise<CryptoKey>);

    expect(algorithm).toBe('AES-GCM');
    expect(extractable).toBeFalse();
    expect(usages).toEqual(['decrypt', 'encrypt']);
    expect(key.extractable).toBeFalse();
    expect([...material].every((byte) => byte === 0)).toBeTrue();
    await expect(
      globalThis.crypto.subtle.exportKey('raw', key),
    ).rejects.toThrow();
  });

  it('seals every frame of a cipher under a fresh nonce', async () => {
    const plaintext = Buffer.from('frame');
    const [first, second] = await Promise.all([
      cipher.seal(plaintext),
      cipher.seal(plaintext),
    ]);

    expect(Buffer.from(first.subarray(5, 17))).not.toEqual(
      Buffer.from(second.subarray(5, 17)),
    );
  });

  it('detects the frame marker', () => {
    expect(CallMediaFrameCipher.hasMarker(frame.subarray(0, 4))).toBeFalse();
    expect(CallMediaFrameCipher.hasMarker(new Uint8Array(40))).toBeFalse();
    expect(CallMediaFrameCipher.hasMarker('PSCE1' as never)).toBeFalse();
  });

  it('seals the largest frame', async () => {
    const plaintext = new Uint8Array(8 * 1024 * 1024).fill(3);

    await expect(cipher.open(await cipher.seal(plaintext))).resolves.toEqual(
      plaintext,
    );
    await expect(
      cipher.seal(new Uint8Array(8 * 1024 * 1024 + 1)),
    ).rejects.toThrow(new InvalidCallMediaFrameError());
  });

  it.each([
    ['another key', SymmetricKey.generate(), frame],
    ['a frame without marker', undefined, frame.subarray(1)],
    ['a truncated frame', undefined, frame.subarray(0, 32)],
    [
      'a tampered frame',
      undefined,
      Buffer.concat([frame.subarray(0, -1), Buffer.from([(frame.at(-1)! + 1) % 256])]),
    ],
    [
      'an oversized frame',
      undefined,
      Buffer.concat([frame.subarray(0, 5), Buffer.alloc(8 * 1024 * 1024 + 29)]),
    ],
    ['a non-byte frame', undefined, 'frame'],
  ])('refuses to open %s', async (_, key, value) => {
    const frameCipher = key
      ? await CallMediaFrameCipher.fromKey(key)
      : cipher;

    await expect(frameCipher.open(value as Uint8Array)).rejects.toThrow(
      InvalidCallMediaFrameError,
    );
  });

  it('refuses to seal non-byte frames', async () => {
    await expect(cipher.seal('frame' as never)).rejects.toThrow(
      InvalidCallMediaFrameError,
    );
  });

  it('refuses keys that are not symmetric keys', async () => {
    await expect(
      CallMediaFrameCipher.fromKey(Buffer.alloc(32) as never),
    ).rejects.toThrow(InvalidCallMediaFrameError);
  });
});
