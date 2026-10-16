import { SymmetricKey } from '../../src';
import { CallMediaFrameContext } from '../../src/internal/CallMediaFrameContext';
import { CallMediaFrameHeader } from '../../src/internal/CallMediaFrameHeader';
import { CallMediaSealerKey } from '../../src/internal/CallMediaSealerKey';
import vectors from '../../vectors/call-media-frame.json';

describe('CallMediaSealerKey', () => {
  afterEach(() => jest.restoreAllMocks());

  it('adds the sequence to the nonce base modulo 2^96', async () => {
    const sealerId = Buffer.from(vectors.sealerId, 'base64url');
    const encrypt = jest.spyOn(globalThis.crypto.subtle, 'encrypt');

    jest
      .spyOn(globalThis.crypto.subtle, 'deriveBits')
      .mockResolvedValueOnce(new Uint8Array(12).fill(255).buffer);
    const key = await CallMediaSealerKey.derive(
      await CallMediaSealerKey.importCallKey(
        SymmetricKey.fromBase64(vectors.key),
      ),
      CallMediaFrameContext.of(vectors.callId, vectors.senderId),
      vectors.epoch,
      sealerId,
      'encrypt',
    );

    await key.seal(
      new CallMediaFrameHeader(vectors.epoch, sealerId, 2),
      'audio',
      new Uint8Array(),
    );

    expect(
      Buffer.from((encrypt.mock.calls[0][0] as AesGcmParams).iv as Uint8Array),
    ).toEqual(Buffer.from([...new Uint8Array(11), 1]));
  });
});
