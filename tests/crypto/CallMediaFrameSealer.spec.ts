import {
  CallMediaFrameOpener,
  CallMediaFrameSealer,
  InvalidCallMediaFrameError,
  SymmetricKey,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import vectors from '../../vectors/call-media-frame.json';

const bytes = (value: string): Buffer => Buffer.from(value, 'base64url');
const callKey = (): SymmetricKey => SymmetricKey.fromBase64(vectors.key);
const context = {
  callId: vectors.callId,
  epoch: vectors.epoch,
  senderId: vectors.senderId,
};

describe('CallMediaFrameSealer', () => {
  afterEach(() => jest.restoreAllMocks());

  it('seals the known-answer frames in sequence', async () => {
    jest
      .spyOn(CryptoAdapter, 'randomBytes')
      .mockReturnValueOnce(bytes(vectors.sealerId));
    const encrypt = jest.spyOn(globalThis.crypto.subtle, 'encrypt');
    const sealer = await CallMediaFrameSealer.create(callKey(), context);

    for (const { frame, plaintext, track } of vectors.frames) {
      expect(
        Buffer.from(await sealer.seal(bytes(plaintext), track)).toString(
          'base64url',
        ),
      ).toBe(frame);
    }
    expect(
      encrypt.mock.calls.map(([algorithm]) =>
        Buffer.from((algorithm as AesGcmParams).iv as Uint8Array).toString(
          'base64url',
        ),
      ),
    ).toEqual(vectors.frames.map(({ nonce }) => nonce));
  });

  it('holds the call key only as a non-extractable HKDF CryptoKey', async () => {
    const importKey = jest.spyOn(globalThis.crypto.subtle, 'importKey');
    const deriveKey = jest.spyOn(globalThis.crypto.subtle, 'deriveKey');

    await CallMediaFrameSealer.create(callKey(), context);
    const [[, material, algorithm, extractable, usages]] = importKey.mock
      .calls as unknown as [[string, Uint8Array, string, boolean, string[]]];
    const root = await (importKey.mock.results[0].value as Promise<CryptoKey>);
    const frameKey = await (deriveKey.mock.results[0]
      .value as Promise<CryptoKey>);

    expect(algorithm).toBe('HKDF');
    expect(extractable).toBeFalse();
    expect(usages).toEqual(['deriveBits', 'deriveKey']);
    expect(root.extractable).toBeFalse();
    expect([...material].every((byte) => byte === 0)).toBeTrue();
    expect(frameKey.extractable).toBeFalse();
    expect(frameKey.usages).toEqual(['encrypt']);
    await expect(
      globalThis.crypto.subtle.exportKey('raw', frameKey),
    ).rejects.toThrow();
  });

  it('gives concurrent frames consecutive sequences and distinct nonces', async () => {
    const encrypt = jest.spyOn(globalThis.crypto.subtle, 'encrypt');
    const sealer = await CallMediaFrameSealer.create(callKey(), context);
    const [first, second] = await Promise.all([
      sealer.seal(Buffer.from('frame'), 'audio'),
      sealer.seal(Buffer.from('frame'), 'audio'),
    ]);
    const [[firstAlgorithm], [secondAlgorithm]] = encrypt.mock.calls;

    expect(Buffer.from(first.subarray(17, 25)).readBigUInt64BE()).toBe(0n);
    expect(Buffer.from(second.subarray(17, 25)).readBigUInt64BE()).toBe(1n);
    expect(
      Buffer.from((firstAlgorithm as AesGcmParams).iv as Uint8Array),
    ).not.toEqual(
      Buffer.from((secondAlgorithm as AesGcmParams).iv as Uint8Array),
    );
  });

  it('gives every sealer its own random sealer id', async () => {
    const [first, second] = await Promise.all([
      CallMediaFrameSealer.create(callKey(), context),
      CallMediaFrameSealer.create(callKey(), context),
    ]);
    const [left, right] = await Promise.all([
      first.seal(Buffer.from('frame'), 'audio'),
      second.seal(Buffer.from('frame'), 'audio'),
    ]);

    expect(Buffer.from(left.subarray(9, 17))).not.toEqual(
      Buffer.from(right.subarray(9, 17)),
    );
  });

  it('seals the largest frame', async () => {
    const sealer = await CallMediaFrameSealer.create(callKey(), context);
    const opener = CallMediaFrameOpener.create(context);
    const plaintext = new Uint8Array(8 * 1024 * 1024).fill(3);

    await opener.addKey(callKey(), vectors.epoch);

    await expect(
      opener.open(await sealer.seal(plaintext, 'video'), 'video'),
    ).resolves.toEqual(plaintext);
    await expect(
      sealer.seal(new Uint8Array(8 * 1024 * 1024 + 1), 'video'),
    ).rejects.toThrow(new InvalidCallMediaFrameError());
  });

  it.each([
    ['a non-symmetric key', Buffer.alloc(32), context],
    ['an empty call id', callKey(), { ...context, callId: '' }],
    [
      'a call id over 256 bytes',
      callKey(),
      { ...context, callId: 'é'.repeat(129) },
    ],
    ['a non-string call id', callKey(), { ...context, callId: 1 }],
    ['an empty sender id', callKey(), { ...context, senderId: '' }],
    [
      'a lone surrogate sender id',
      callKey(),
      { ...context, senderId: '\uD800' },
    ],
    ['a negative epoch', callKey(), { ...context, epoch: -1 }],
    ['a fractional epoch', callKey(), { ...context, epoch: 1.5 }],
    ['an epoch past 32 bits', callKey(), { ...context, epoch: 2 ** 32 }],
    ['a string epoch', callKey(), { ...context, epoch: '7' }],
    ['no context', callKey(), undefined],
  ])('refuses to create a sealer with %s', async (_, key, value) => {
    await expect(
      CallMediaFrameSealer.create(key as SymmetricKey, value as never),
    ).rejects.toThrow(InvalidCallMediaFrameError);
  });

  it.each([
    ['a non-byte frame', 'frame', 'audio'],
    ['an empty track', Buffer.from('frame'), ''],
    ['a track over 64 bytes', Buffer.from('frame'), 'a'.repeat(65)],
    ['a non-string track', Buffer.from('frame'), 1],
  ])('refuses to seal %s', async (_, frame, track) => {
    const sealer = await CallMediaFrameSealer.create(callKey(), context);

    await expect(
      sealer.seal(frame as Uint8Array, track as string),
    ).rejects.toThrow(InvalidCallMediaFrameError);
  });
});
