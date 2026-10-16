import {
  CallMediaFrameOpener,
  CallMediaFrameSealer,
  InvalidCallMediaFrameError,
  SymmetricKey,
} from '../../src';
import vectors from '../../vectors/call-media-frame.json';

const bytes = (value: string): Buffer => Buffer.from(value, 'base64url');
const callKey = SymmetricKey.fromBase64(vectors.key);
const peer = { callId: vectors.callId, senderId: vectors.senderId };
const [first, second] = vectors.frames.map(({ frame }) => bytes(frame));
const invalid = new InvalidCallMediaFrameError();

const opener = async (
  keys: [SymmetricKey, number][] = [[callKey, vectors.epoch]],
): Promise<CallMediaFrameOpener> => {
  const created = CallMediaFrameOpener.create(peer);

  for (const [key, epoch] of keys) await created.addKey(key, epoch);

  return created;
};
const sealer = (
  epoch = vectors.epoch,
  key = callKey,
): Promise<CallMediaFrameSealer> =>
  CallMediaFrameSealer.create(key, { ...peer, epoch });
const flip = (frame: Uint8Array, index: number): Buffer => {
  const copy = Buffer.from(frame);

  copy[index] = (copy[index] + 1) % 256;

  return copy;
};

describe('CallMediaFrameOpener', () => {
  afterEach(() => jest.restoreAllMocks());

  it('opens the known-answer frames', async () => {
    const frames = await opener();

    for (const { frame, plaintext, track } of [
      ...vectors.frames,
      vectors.maxSequenceFrame,
    ]) {
      expect(
        Buffer.from(await frames.open(bytes(frame), track)).toString(
          'base64url',
        ),
      ).toBe(plaintext);
    }
  });

  it('derives non-extractable decrypt-only frame keys', async () => {
    const deriveKey = jest.spyOn(globalThis.crypto.subtle, 'deriveKey');

    await (await opener()).open(first, 'audio');
    const frameKey = await (deriveKey.mock.results[0]
      .value as Promise<CryptoKey>);

    expect(frameKey.extractable).toBeFalse();
    expect(frameKey.usages).toEqual(['decrypt']);
  });

  it('opens frames out of order within the replay window', async () => {
    const frames = await opener();

    await expect(frames.open(second, 'video')).resolves.toBeDefined();
    await expect(frames.open(first, 'audio')).resolves.toBeDefined();
  });

  it('opens every frame at most once', async () => {
    const frames = await opener();

    await frames.open(first, 'audio');

    await expect(frames.open(first, 'audio')).rejects.toThrow(invalid);
  });

  it('opens at most one of two concurrent copies of a frame', async () => {
    const frames = await opener();
    const results = await Promise.allSettled([
      frames.open(first, 'audio'),
      frames.open(first, 'audio'),
    ]);

    expect(results.map(({ status }) => status).sort()).toEqual([
      'fulfilled',
      'rejected',
    ]);
  });

  it('shares the replay window of concurrent first frames of a sealer', async () => {
    const frames = await opener();

    await Promise.all([
      frames.open(first, 'audio'),
      frames.open(second, 'video'),
    ]);

    await expect(frames.open(second, 'video')).rejects.toThrow(invalid);
  });

  it('refuses frames at or below the replay window', async () => {
    const frameSealer = await sealer();
    const frames = await opener();
    const sealed: Uint8Array[] = [];

    for (let sequence = 0; sequence < 1100; sequence += 1)
      sealed.push(
        await frameSealer.seal(Buffer.from([sequence % 256]), 'audio'),
      );
    await frames.open(sealed[1099], 'audio');

    await expect(frames.open(sealed[75], 'audio')).rejects.toThrow(invalid);
    await expect(frames.open(sealed[76], 'audio')).resolves.toEqual(
      Buffer.from([76]),
    );
  });

  it('keeps forged frames from consuming sequences', async () => {
    const frames = await opener();

    await expect(
      frames.open(flip(first, first.length - 1), 'audio'),
    ).rejects.toThrow(invalid);
    await expect(frames.open(first, 'audio')).resolves.toBeDefined();
  });

  it('retains at most 64 sealers per epoch', async () => {
    const frames = await opener();
    const sealers = await Promise.all(
      Array.from({ length: 65 }, () => sealer()),
    );

    for (const frameSealer of sealers.slice(0, 64))
      await frames.open(
        await frameSealer.seal(Buffer.from('a'), 'audio'),
        'audio',
      );

    await expect(
      frames.open(await sealers[64].seal(Buffer.from('a'), 'audio'), 'audio'),
    ).rejects.toThrow(invalid);
    await expect(
      frames.open(await sealers[0].seal(Buffer.from('b'), 'audio'), 'audio'),
    ).resolves.toEqual(Buffer.from('b'));
  });

  it('refuses the second of two concurrent new sealers past the limit', async () => {
    const frames = await opener();
    const sealers = await Promise.all(
      Array.from({ length: 65 }, () => sealer()),
    );

    for (const frameSealer of sealers.slice(0, 63))
      await frames.open(
        await frameSealer.seal(Buffer.from('a'), 'audio'),
        'audio',
      );
    const [left, right] = await Promise.all([
      sealers[63].seal(Buffer.from('a'), 'audio'),
      sealers[64].seal(Buffer.from('a'), 'audio'),
    ]);
    const results = await Promise.allSettled([
      frames.open(left, 'audio'),
      frames.open(right, 'audio'),
    ]);

    expect(results.map(({ status }) => status).sort()).toEqual([
      'fulfilled',
      'rejected',
    ]);
  });

  it('drops older epochs once a frame of a newer epoch opens', async () => {
    const nextKey = SymmetricKey.generate();
    const frames = await opener([
      [callKey, vectors.epoch],
      [nextKey, vectors.epoch + 1],
    ]);
    const next = await sealer(vectors.epoch + 1, nextKey);

    await expect(frames.open(first, 'audio')).resolves.toBeDefined();
    await frames.open(await next.seal(Buffer.from('a'), 'audio'), 'audio');

    await expect(frames.open(second, 'video')).rejects.toThrow(invalid);
  });

  it('refuses an older-epoch frame that authenticates after a newer one', async () => {
    const nextKey = SymmetricKey.generate();
    const frames = await opener([
      [callKey, vectors.epoch],
      [nextKey, vectors.epoch + 1],
    ]);
    const next = await sealer(vectors.epoch + 1, nextKey);
    const newer = await next.seal(Buffer.from('a'), 'audio');
    const decrypt = globalThis.crypto.subtle.decrypt.bind(
      globalThis.crypto.subtle,
    );
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));

    await frames.open(first, 'audio');
    jest
      .spyOn(globalThis.crypto.subtle, 'decrypt')
      .mockImplementationOnce(async (...args) => {
        await gate;

        return decrypt(...args);
      });
    const older = frames.open(second, 'video');

    await frames.open(newer, 'audio');
    release();

    await expect(older).rejects.toThrow(invalid);
  });

  it('holds only the two newest epochs', async () => {
    const frames = await opener([
      [callKey, vectors.epoch],
      [SymmetricKey.generate(), vectors.epoch + 1],
      [SymmetricKey.generate(), vectors.epoch + 2],
    ]);

    await expect(frames.open(first, 'audio')).rejects.toThrow(invalid);
  });

  it('takes concurrent keys of increasing epochs', async () => {
    const frames = CallMediaFrameOpener.create(peer);

    await Promise.all([
      frames.addKey(callKey, vectors.epoch),
      frames.addKey(SymmetricKey.generate(), vectors.epoch + 1),
    ]);

    await expect(frames.open(first, 'audio')).resolves.toBeDefined();
  });

  it.each([
    ['the same epoch', vectors.epoch],
    ['an older epoch', vectors.epoch - 1],
    ['a negative epoch', -1],
    ['an epoch past 32 bits', 2 ** 32],
    ['a fractional epoch', 7.5],
  ])('refuses a key for %s', async (_, epoch) => {
    const frames = await opener();

    await expect(frames.addKey(callKey, epoch)).rejects.toThrow(invalid);
  });

  it('refuses keys that are not symmetric keys', async () => {
    await expect(
      CallMediaFrameOpener.create(peer).addKey(Buffer.alloc(32) as never, 1),
    ).rejects.toThrow(invalid);
  });

  it('refuses frames of a key the platform could not import', async () => {
    const frames = CallMediaFrameOpener.create(peer);

    jest
      .spyOn(globalThis.crypto.subtle, 'importKey')
      .mockRejectedValueOnce(new Error('import failed'));

    await expect(frames.addKey(callKey, vectors.epoch)).rejects.toThrow(
      invalid,
    );
    await expect(frames.open(first, 'audio')).rejects.toThrow(invalid);
  });

  it.each([
    ['an empty call id', { ...peer, callId: '' }],
    ['a call id over 256 bytes', { ...peer, callId: 'a'.repeat(257) }],
    ['a non-string sender id', { ...peer, senderId: 1 }],
    ['no peer', undefined],
  ])('refuses to create an opener with %s', (_, value) => {
    expect(() => CallMediaFrameOpener.create(value as never)).toThrow(invalid);
  });

  it.each([
    ['another call', { ...peer, callId: 'call-2' }, first, 'audio'],
    ['another sender', { ...peer, senderId: 'identity-bob' }, first, 'audio'],
    ['another track', peer, first, 'video'],
    ['an invalid track', peer, first, ''],
    ['a tampered marker', peer, flip(first, 4), 'audio'],
    ['a tampered epoch', peer, flip(first, 8), 'audio'],
    ['a tampered sealer id', peer, flip(first, 9), 'audio'],
    ['a tampered sequence', peer, flip(first, 24), 'audio'],
    ['a tampered tag', peer, flip(first, first.length - 1), 'audio'],
    [
      'a sequence past 2^53 - 1',
      peer,
      Buffer.concat([
        first.subarray(0, 17),
        Buffer.alloc(8, 255),
        first.subarray(25),
      ]),
      'audio',
    ],
    ['a truncated frame', peer, first.subarray(0, 40), 'audio'],
    ['a frame shorter than its header', peer, first.subarray(0, 24), 'audio'],
    [
      'an oversized frame',
      peer,
      Buffer.concat([
        first.subarray(0, 25),
        Buffer.alloc(8 * 1024 * 1024 + 17),
      ]),
      'audio',
    ],
    ['a non-byte frame', peer, 'frame', 'audio'],
  ])('refuses to open a frame for %s', async (_, value, frame, track) => {
    const frames = CallMediaFrameOpener.create(value);

    await frames.addKey(callKey, vectors.epoch);

    await expect(frames.open(frame as Uint8Array, track)).rejects.toThrow(
      invalid,
    );
  });

  it('refuses frames under another key', async () => {
    const frames = await opener([[SymmetricKey.generate(), vectors.epoch]]);

    await expect(frames.open(first, 'audio')).rejects.toThrow(invalid);
  });
});
