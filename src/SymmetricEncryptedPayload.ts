import { EncryptedPayload } from './EncryptedPayload';
import { EncryptedPayloadScheme } from './EncryptedPayloadScheme';

export class SymmetricEncryptedPayload extends EncryptedPayload {
  public getScheme(): EncryptedPayloadScheme {
    return 'symmetric';
  }
}
