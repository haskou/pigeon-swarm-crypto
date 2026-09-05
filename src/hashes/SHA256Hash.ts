import {
  Media,
  SHA256Hash as ValueObjectSHA256Hash,
} from '@haskou/value-objects';

import { CryptoAdapter } from '../internal/CryptoAdapter';
import { HashPayload } from './HashPayload';

export class SHA256Hash extends ValueObjectSHA256Hash {
  public static from(payload: HashPayload): SHA256Hash {
    return new SHA256Hash(
      CryptoAdapter.hash(
        'sha256',
        payload instanceof Media ? payload.getBuffer() : payload.valueOf(),
      ),
    );
  }
}
