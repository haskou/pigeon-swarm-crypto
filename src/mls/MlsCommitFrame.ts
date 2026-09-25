import { FrameKind, MlsFrame } from './internal/MlsFrame';

export class MlsCommitFrame extends MlsFrame {
  public static create(payload: Uint8Array): MlsCommitFrame {
    return new MlsCommitFrame(MlsFrame.validatePayload(payload));
  }

  public static fromBytes(bytes: Uint8Array): MlsCommitFrame {
    return new MlsCommitFrame(MlsFrame.parse(bytes, FrameKind.Commit));
  }

  private constructor(payload: Uint8Array) {
    super(FrameKind.Commit, payload);
  }
}
