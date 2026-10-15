import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { PrivateKey } from '../src/PrivateKey';
import { PublicKey } from '../src/PublicKey';

export type VectorKey = Readonly<{
  identityId: string;
  privateKeyPem: string;
  publicKeyPem: string;
}>;

/** Reads one shipped `vectors/<name>.json` file, as consumers do. */
export const loadVectors = <T>(name: string): T =>
  JSON.parse(
    readFileSync(join(__dirname, '..', 'vectors', `${name}.json`), 'utf8'),
  ) as T;

export const privateKeyOf = (key: VectorKey): PrivateKey =>
  PrivateKey.fromPEM(key.privateKeyPem);

export const publicKeyOf = (key: VectorKey): PublicKey =>
  new PublicKey(key.publicKeyPem);
