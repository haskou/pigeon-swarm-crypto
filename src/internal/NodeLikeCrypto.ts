import type { Buffer } from 'buffer';

export type NodeLikeCrypto = {
  randomBytes?: (
    size: number,
    callback: (err: Error | null, bytes: Buffer) => void,
  ) => void;
  scrypt?: (
    password: string,
    salt: Buffer,
    keylen: number,
    options: { N: number; r: number; p: number },
    callback: (err: Error | null, key: Buffer) => void,
  ) => void;
};
