import { InvalidMlsFrameError } from '../../src/mls/InvalidMlsFrameError';
import { MlsApplicationFrame } from '../../src/mls/MlsApplicationFrame';
import { MlsCommitFrame } from '../../src/mls/MlsCommitFrame';
import { MlsWelcomeFrame } from '../../src/mls/MlsWelcomeFrame';

describe('MLS wire frames', () => {
  const payload = Uint8Array.of(1, 2, 3);

  it.each([
    MlsApplicationFrame,
    MlsCommitFrame,
    MlsWelcomeFrame,
  ])('round-trips a %p without exposing mutable storage', (Frame) => {
    const frame = Frame.create(payload);
    const encoded = frame.toBytes();
    const restored = Frame.fromBytes(encoded);
    encoded.fill(0);
    const restoredPayload = restored.payloadBytes();
    restoredPayload.fill(0);

    expect(Array.from(restored.payloadBytes())).toEqual([1, 2, 3]);
  });

  it('rejects malformed, oversized and cross-kind frames', () => {
    const application = MlsApplicationFrame.create(payload).toBytes();
    const oversized = new Uint8Array(1024 * 1024 + 1);

    expect(() => MlsApplicationFrame.create(new Uint8Array(0))).toThrow(
      InvalidMlsFrameError,
    );
    expect(() => MlsApplicationFrame.create(oversized)).toThrow(
      InvalidMlsFrameError,
    );
    expect(() => MlsCommitFrame.fromBytes(application)).toThrow(
      InvalidMlsFrameError,
    );
    expect(() => MlsApplicationFrame.fromBytes(new Uint8Array(0))).toThrow(
      InvalidMlsFrameError,
    );
  });
});
