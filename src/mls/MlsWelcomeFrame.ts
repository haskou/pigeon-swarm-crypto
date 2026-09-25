import { FrameKind, MlsFrame } from './internal/MlsFrame';

export class MlsWelcomeFrame extends MlsFrame {
  public static create(payload: Uint8Array): MlsWelcomeFrame {
    return new MlsWelcomeFrame(MlsFrame.validatePayload(payload));
  }

  public static fromBytes(bytes: Uint8Array): MlsWelcomeFrame {
    return new MlsWelcomeFrame(MlsFrame.parse(bytes, FrameKind.Welcome));
  }

  private constructor(payload: Uint8Array) {
    super(FrameKind.Welcome, payload);
  }
}
