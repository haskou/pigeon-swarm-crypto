import { MD5Hash as ValueObjectMD5Hash, Media } from '@haskou/value-objects';

import { CryptoAdapter } from '../internal/CryptoAdapter';
import { HashPayload } from './HashPayload';

export class MD5Hash extends ValueObjectMD5Hash {
  public static from(payload: HashPayload): MD5Hash {
    return new MD5Hash(
      CryptoAdapter.hash(
        'md5',
        payload instanceof Media ? payload.getBuffer() : payload.valueOf(),
      ),
    );
  }
}
