import {
  Media,
  SHA512Hash as ValueObjectSHA512Hash,
} from '@haskou/value-objects';

import { CryptoAdapter } from '../internal/CryptoAdapter';
import { HashPayload } from './HashPayload';

export class SHA512Hash extends ValueObjectSHA512Hash {
  public static from(payload: HashPayload): SHA512Hash {
    return new SHA512Hash(
      CryptoAdapter.hash(
        'sha512',
        payload instanceof Media ? payload.getBuffer() : payload.valueOf(),
      ),
    );
  }
}
