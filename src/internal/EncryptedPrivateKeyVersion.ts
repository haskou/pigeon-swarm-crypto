import { CryptoPassword } from '../CryptoPassword';
import { PrivateKey } from '../PrivateKey';

export abstract class EncryptedPrivateKeyVersion {
  public abstract matches(parts: string[]): boolean;
  public abstract decrypt(
    parts: string[],
    password: CryptoPassword,
  ): Promise<PrivateKey>;

  public needsReEncryption(): boolean {
    return false;
  }
}
