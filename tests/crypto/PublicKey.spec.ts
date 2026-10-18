import {
  InvalidFormatError,
  InvalidLengthError,
  Media,
  NullObject,
  StringValueObject,
} from '@haskou/value-objects';
import * as crypto from 'node:crypto';

import {
  AsymmetricEncryptedPayload,
  EncryptedPayload,
  Key,
  PrivateKey,
  PublicKey,
  Signature,
} from '../../src';

describe('PublicKey', () => {
  let privatePem: string;
  let publicPem: string;

  beforeAll(() => {
    const pair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    privatePem = pair.privateKey;
    publicPem = pair.publicKey;
  });

  it('validates constructor input', () => {
    expect(
      NullObject.isNullObject(new PublicKey(undefined as unknown as string)),
    ).toBeTrue();
    expect(
      NullObject.isNullObject(new PublicKey(null as unknown as string)),
    ).toBeTrue();
    expect(new PublicKey(publicPem).valueOf()).toBe(publicPem);
    expect(() => new PublicKey('short')).toThrow(InvalidLengthError);
    expect(() => new PublicKey('a'.repeat(113))).toThrow(InvalidFormatError);
    expect(() => new PublicKey(privatePem)).toThrow(InvalidLengthError);
  });

  it('creates keys from PEM strings and VOs', () => {
    expect(PublicKey.fromPEM(publicPem).valueOf()).toBe(publicPem);
    expect(PublicKey.fromPEM(new StringValueObject(publicPem)).valueOf()).toBe(
      publicPem,
    );
  });

  it('verifies valid signatures and rejects invalid ones', () => {
    const key = new PublicKey(publicPem);
    const valid = Signature.fromBuffer(
      crypto.sign(null, Buffer.from('message'), privatePem),
    );
    const invalid = Signature.fromBuffer(
      crypto.sign(null, Buffer.from('other'), privatePem),
    );

    expect(key.isValidSignature('message', valid)).toBeTrue();
    expect(key.isValidSignature('tampered', valid)).toBeFalse();
    expect(key.isValidSignature('message', invalid)).toBeFalse();
    expect(
      key.isValidSignature(new StringValueObject('message'), valid),
    ).toBeTrue();
  });

  it('verifies signatures over raw Media bytes', () => {
    const payload = Buffer.from([0xff, 0xfe, 0xfd, 0, 0x80]);
    const signature = Signature.fromBuffer(
      crypto.sign(null, payload, privatePem),
    );
    expect(
      new PublicKey(publicPem).isValidSignature(new Media(payload), signature),
    ).toBeTrue();
  });

  describe('strict Ed25519 verification (RFC 8032, no small-order keys)', () => {
    const pemFromRawKey = (rawKeyHex: string): PublicKey =>
      new PublicKey(
        `-----BEGIN PUBLIC KEY-----\n${Buffer.concat([
          Buffer.from('302a300506032b6570032100', 'hex'),
          Buffer.from(rawKeyHex, 'hex'),
        ]).toString('base64')}\n-----END PUBLIC KEY-----\n`,
      );
    const signatureFromHex = (hex: string): Signature =>
      Signature.fromBuffer(Buffer.from(hex, 'hex'));
    const honestKey =
      '78899ded7ed71ce8c18552165d02ac87bd63b91191952c4e90798f2430542b7e';
    const smallOrderKey = `01${'00'.repeat(31)}`;
    const nonCanonicalIdentity = `ee${'ff'.repeat(30)}7f`;
    const identitySignature = `01${'00'.repeat(63)}`;

    it('accepts the honest signature of the known-answer key', () => {
      expect(
        pemFromRawKey(honestKey).isValidSignature(
          'message',
          signatureFromHex(
            'd05e6ca2a45dab9011f4cb2dbb45c293ab74909103e0680f074a8748ec946a76c9edf57575ac7b6d79d162163e38b1cfab1376df84379ca7e96ee6ee16af6305',
          ),
        ),
      ).toBeTrue();
    });

    it('rejects a small-order public key that verifies any message', () => {
      const key = pemFromRawKey(smallOrderKey);
      const signature = signatureFromHex(identitySignature);

      expect(key.isValidSignature('message', signature)).toBeFalse();
      expect(key.isValidSignature('anything', signature)).toBeFalse();
    });

    it('rejects a non-canonical encoding of the identity public key', () => {
      expect(
        pemFromRawKey(nonCanonicalIdentity).isValidSignature(
          'message',
          signatureFromHex(identitySignature),
        ),
      ).toBeFalse();
    });

    it('rejects a non-canonical R encoding under an honest key', () => {
      expect(
        pemFromRawKey(honestKey).isValidSignature(
          'message',
          signatureFromHex(
            `${nonCanonicalIdentity}bb9dc62ee84724b85b0fa54b6ad67c83b0835966a3ca39f2ca6f22f15f6b1b0f`,
          ),
        ),
      ).toBeFalse();
    });
  });

  it('encrypts versioned payloads with fresh ephemeral keys and IVs', () => {
    const key = new PublicKey(publicPem);
    const first = key.encrypt('same payload');
    const second = key.encrypt('same payload');
    const parts = first.valueOf().split('.');

    expect(first).toBeInstanceOf(AsymmetricEncryptedPayload);
    expect(first).toBeInstanceOf(EncryptedPayload);
    expect(first.getScheme()).toBe('asymmetric');
    expect(parts).toHaveLength(6);
    expect(parts[0]).toBe('v2');
    expect(parts[1]).toBe('x25519-hkdf-sha256-aes-256-gcm');
    expect(Buffer.from(parts[2], 'base64')).toHaveLength(32);
    expect(Buffer.from(parts[3], 'base64')).toHaveLength(12);
    expect(Buffer.from(parts[5], 'base64')).toHaveLength(16);
    expect(parts[2]).not.toBe(second.valueOf().split('.')[2]);
    expect(parts[3]).not.toBe(second.valueOf().split('.')[3]);
  });

  it('encrypts VO and Media payloads and round-trips through PrivateKey', () => {
    const pub = new PublicKey(publicPem);
    const priv = new PrivateKey(privatePem);
    const vo = pub.encrypt(new StringValueObject('hello'));
    const bytes = Buffer.from([0xff, 0xfe, 0xfd, 0, 0x80]);
    const media = pub.encrypt(new Media(bytes));

    expect(priv.decrypt(vo).toString()).toBe('hello');
    expect(priv.decrypt(media)).toEqual(bytes);
  });

  it('rejects oversized payloads', () => {
    expect(() =>
      new PublicKey(publicPem).encrypt(Buffer.alloc(1024 * 1024 + 1)),
    ).toThrow(InvalidLengthError);
  });

  it('keeps Key and ValueObject behavior', () => {
    const first = new PublicKey(publicPem);
    const second = new PublicKey(publicPem);
    const cloned = (first as any).clone();
    const other = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });

    expect(first).toBeInstanceOf(Key);
    expect(first.isEqual(second)).toBeTrue();
    expect(first.isEqual(publicPem)).toBeFalse();
    expect(first.hasValue(publicPem)).toBeTrue();
    expect(first.isEqual(new PublicKey(other.publicKey))).toBeFalse();
    expect(cloned).toBeInstanceOf(PublicKey);
    expect(cloned.valueOf()).toBe(publicPem);
    expect(cloned).not.toBe(first);
  });
});

describe('PublicKey raw Ed25519 encoding', () => {
  const rfc8032Public = Buffer.from(
    'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    'hex',
  );
  const pemOf = (prefix: string, raw: Buffer): string =>
    `-----BEGIN PUBLIC KEY-----\n${Buffer.concat([
      Buffer.from(prefix, 'hex'),
      raw,
    ]).toString('base64')}\n-----END PUBLIC KEY-----\n`;
  const ed25519Prefix = '302a300506032b6570032100';
  const smallOrder = Buffer.from(`01${'00'.repeat(31)}`, 'hex');

  it('round-trips the RFC 8032 public key through SPKI', () => {
    const key = PublicKey.fromRaw(Uint8Array.from(rfc8032Public));
    const native = crypto.createPublicKey(key.valueOf());

    expect(
      native.export({ format: 'der', type: 'spki' }).subarray(-32),
    ).toEqual(rfc8032Public);
    expect(Buffer.from(key.toRaw())).toEqual(rfc8032Public);
    expect(key.toRaw()).not.toBe(key.toRaw());
    expect(
      Buffer.from(new PublicKey(pemOf(ed25519Prefix, rfc8032Public)).toRaw()),
    ).toEqual(rfc8032Public);
  });

  it('rejects raw keys that are not strict Ed25519 points', () => {
    for (const raw of [
      smallOrder,
      rfc8032Public.subarray(1),
      Buffer.concat([rfc8032Public, Buffer.alloc(1)]),
      Buffer.alloc(32, 0xff),
      undefined,
      'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    ])
      expect(() => PublicKey.fromRaw(raw as unknown as Uint8Array)).toThrow(
        InvalidFormatError,
      );
  });

  it('refuses to export non Ed25519, small-order or non-canonical SPKI keys', () => {
    const canonical = pemOf(ed25519Prefix, rfc8032Public);
    const padding = canonical.indexOf('=\n');
    const alphabet =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    const nonCanonical = `${canonical.slice(0, padding - 1)}${
      alphabet[alphabet.indexOf(canonical[padding - 1]) + 1]
    }${canonical.slice(padding)}`;

    expect(Buffer.from(nonCanonical.split('\n')[1], 'base64')).toEqual(
      Buffer.from(canonical.split('\n')[1], 'base64'),
    );
    for (const pem of [
      pemOf('302a300506032b656e032100', rfc8032Public),
      pemOf(ed25519Prefix, smallOrder),
      nonCanonical,
    ])
      expect(() => new PublicKey(pem).toRaw()).toThrow(InvalidFormatError);
  });
});

describe('PublicKey subclasses whose valueOf() is bare base64', () => {
  let publicPem: string;
  let privatePem: string;
  let bareBase64: string;

  beforeAll(() => {
    const pair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    publicPem = pair.publicKey;
    privatePem = pair.privateKey;
    bareBase64 = publicPem
      .replace('-----BEGIN PUBLIC KEY-----\n', '')
      .replace('\n-----END PUBLIC KEY-----\n', '');
  });

  class IdentityId extends PublicKey {
    public override valueOf(): string {
      return bareBase64;
    }
  }

  it('converts to raw bytes through the canonical PEM form', () => {
    expect(new IdentityId(publicPem).toRaw()).toEqual(
      new PublicKey(publicPem).toRaw(),
    );
  });

  it('verifies signatures through the canonical PEM form', () => {
    const valid = Signature.fromBuffer(
      crypto.sign(null, Buffer.from('message'), privatePem),
    );
    const invalid = Signature.fromBuffer(
      crypto.sign(null, Buffer.from('other'), privatePem),
    );

    expect(
      new IdentityId(publicPem).isValidSignature('message', valid),
    ).toBeTrue();
    expect(
      new IdentityId(publicPem).isValidSignature('message', invalid),
    ).toBeFalse();
  });

  it('encrypts to the canonical PEM form and round-trips through PrivateKey', () => {
    const payload = new IdentityId(publicPem).encrypt('hello');

    expect(new PrivateKey(privatePem).decrypt(payload).toString()).toBe(
      'hello',
    );
  });

  it('keeps canonical PEM keys working alongside the subclass', () => {
    const key = new PublicKey(publicPem);

    expect(key.toRaw()).toHaveLength(32);
    expect(
      key.isValidSignature(
        'message',
        Signature.fromBuffer(
          crypto.sign(null, Buffer.from('message'), privatePem),
        ),
      ),
    ).toBeTrue();
    expect(
      new PrivateKey(privatePem).decrypt(key.encrypt('hi')).toString(),
    ).toBe('hi');
  });
});
