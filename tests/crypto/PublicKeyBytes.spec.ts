import * as crypto from 'node:crypto';

import { InvalidEd25519PublicKeyError } from '../../src/errors/InvalidEd25519PublicKeyError';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';

const ed25519Prefix = Buffer.from('302a300506032b6570032100', 'hex');

const pemOf = (der: Buffer): string =>
  `-----BEGIN PUBLIC KEY-----\n${der.toString('base64')}\n-----END PUBLIC KEY-----\n`;

describe('CryptoAdapter.publicKeyToBytes', () => {
  let publicPem: string;
  let rawKey: Buffer;

  beforeAll(() => {
    const pair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    publicPem = pair.publicKey;
    rawKey = Buffer.from(
      crypto.createPublicKey(publicPem).export({ format: 'der', type: 'spki' }),
    ).subarray(ed25519Prefix.length);
  });

  it('returns the 32-byte key of a valid Ed25519 SPKI PEM', () => {
    expect(rawKey).toHaveLength(32);
    expect(Buffer.from(CryptoAdapter.publicKeyToBytes(publicPem))).toEqual(
      rawKey,
    );
  });

  it('rejects a wrong 12-byte prefix', () => {
    const prefix = Buffer.from(ed25519Prefix);
    prefix[prefix.length - 1] = prefix[prefix.length - 1] === 0 ? 1 : 0;

    expect(() =>
      CryptoAdapter.publicKeyToBytes(pemOf(Buffer.concat([prefix, rawKey]))),
    ).toThrow(InvalidEd25519PublicKeyError);
  });

  it('rejects keys that are not 32 bytes long', () => {
    expect(() =>
      CryptoAdapter.publicKeyToBytes(
        pemOf(Buffer.concat([ed25519Prefix, rawKey, Buffer.from([0])])),
      ),
    ).toThrow(InvalidEd25519PublicKeyError);
    expect(() =>
      CryptoAdapter.publicKeyToBytes(
        pemOf(Buffer.concat([ed25519Prefix, rawKey.subarray(1)])),
      ),
    ).toThrow(InvalidEd25519PublicKeyError);
  });

  it('rejects truncated DER', () => {
    const der = Buffer.concat([ed25519Prefix, rawKey]);

    expect(() =>
      CryptoAdapter.publicKeyToBytes(pemOf(der.subarray(0, 20))),
    ).toThrow(InvalidEd25519PublicKeyError);
    expect(() =>
      CryptoAdapter.publicKeyToBytes(pemOf(Buffer.alloc(0))),
    ).toThrow(InvalidEd25519PublicKeyError);
  });

  it('rejects non-Ed25519 SPKI key types', () => {
    const x25519 = crypto.generateKeyPairSync('x25519', {
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    }).publicKey;
    const p256 = crypto.generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    }).publicKey;
    const rsa = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    }).publicKey;

    for (const pem of [x25519, p256, rsa]) {
      expect(() => CryptoAdapter.publicKeyToBytes(pem)).toThrow(
        InvalidEd25519PublicKeyError,
      );
    }
  });

  it('rejects garbage base64', () => {
    expect(() =>
      CryptoAdapter.publicKeyToBytes(
        '-----BEGIN PUBLIC KEY-----\n!!!not-base64!!!\n-----END PUBLIC KEY-----\n',
      ),
    ).toThrow(InvalidEd25519PublicKeyError);
  });

  it('keeps the strict variant empty for malformed input', () => {
    const prefix = Buffer.from(ed25519Prefix);
    prefix[0] = prefix[0] === 0 ? 1 : 0;

    expect(
      CryptoAdapter.publicKeyToStrictBytes(
        pemOf(Buffer.concat([prefix, rawKey])),
      ),
    ).toHaveLength(0);
  });

  it('does not echo key material in the error message', () => {
    const short = rawKey.subarray(1);
    const pem = pemOf(Buffer.concat([ed25519Prefix, short]));

    let thrown: unknown;
    try {
      CryptoAdapter.publicKeyToBytes(pem);
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(InvalidEd25519PublicKeyError);
    const message = (thrown as Error).message;
    expect(message).not.toContain(short.toString('base64'));
    expect(message).not.toContain(short.toString('hex'));
    expect(message).not.toContain(rawKey.toString('base64'));
  });
});

describe('CryptoAdapter.publicKeyToBytes PEM shape', () => {
  const pair = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { format: 'pem', type: 'spki' },
  });
  const pem = pair.publicKey;
  const body = pem
    .replace('-----BEGIN PUBLIC KEY-----\n', '')
    .replace('\n-----END PUBLIC KEY-----\n', '');

  it('rejects input without armor', () => {
    expect(() => CryptoAdapter.publicKeyToBytes(body)).toThrow(
      InvalidEd25519PublicKeyError,
    );
  });

  it('rejects a missing trailing newline', () => {
    expect(() => CryptoAdapter.publicKeyToBytes(pem.trimEnd())).toThrow(
      InvalidEd25519PublicKeyError,
    );
  });

  it('rejects CRLF line endings', () => {
    expect(() =>
      CryptoAdapter.publicKeyToBytes(pem.replace(/\n/g, '\r\n')),
    ).toThrow(InvalidEd25519PublicKeyError);
  });

  it('rejects trailing data after the END marker', () => {
    expect(() => CryptoAdapter.publicKeyToBytes(`${pem}extra`)).toThrow(
      InvalidEd25519PublicKeyError,
    );
    expect(() => CryptoAdapter.publicKeyToBytes(`${pem}\n`)).toThrow(
      InvalidEd25519PublicKeyError,
    );
  });

  it('rejects a second PEM block', () => {
    expect(() => CryptoAdapter.publicKeyToBytes(`${pem}${pem}`)).toThrow(
      InvalidEd25519PublicKeyError,
    );
  });

  it('rejects injected markers inside the body', () => {
    const injected = `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;

    expect(() => CryptoAdapter.publicKeyToBytes(injected)).toThrow(
      InvalidEd25519PublicKeyError,
    );
    expect(() =>
      CryptoAdapter.publicKeyToBytes(
        `-----BEGIN PUBLIC KEY-----\n${body.slice(0, 20)}\n-----END PUBLIC KEY-----\n${body.slice(20)}\n`,
      ),
    ).toThrow(InvalidEd25519PublicKeyError);
  });
});
