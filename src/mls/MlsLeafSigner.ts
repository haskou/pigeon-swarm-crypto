import type { KeyPair } from '../KeyPair';
import type { MlsLeafOwner } from './MlsLeafOwner';

/** Signs a leaf credential with the owning identity's and device's keys. */
export class MlsLeafSigner {
  constructor(
    public readonly owner: MlsLeafOwner,
    private readonly identityKey: Pick<KeyPair, 'sign'>,
    private readonly deviceKey: Pick<KeyPair, 'sign'>,
  ) {}

  public sign(message: string): { device: string; identity: string } {
    return {
      device: this.deviceKey.sign(message).valueOf(),
      identity: this.identityKey.sign(message).valueOf(),
    };
  }
}
