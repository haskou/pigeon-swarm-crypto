import { EncryptedPayload } from './EncryptedPayload';
import { EncryptedPayloadScheme } from './EncryptedPayloadScheme';

export class AsymmetricEncryptedPayload extends EncryptedPayload {
  public getScheme(): EncryptedPayloadScheme {
    return 'asymmetric';
  }
}
