import { FrameKind, MlsFrame } from './internal/MlsFrame';

export class MlsApplicationFrame extends MlsFrame {
  public static create(payload: Uint8Array): MlsApplicationFrame {
    return new MlsApplicationFrame(MlsFrame.validatePayload(payload));
  }

  public static fromBytes(bytes: Uint8Array): MlsApplicationFrame {
    return new MlsApplicationFrame(
      MlsFrame.parse(bytes, FrameKind.Application),
    );
  }

  private constructor(payload: Uint8Array) {
    super(FrameKind.Application, payload);
  }
}
