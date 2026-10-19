import {
  DomainError,
  InvalidLengthError,
  Media,
} from '@haskou/value-objects';
import * as crypto from 'node:crypto';

import {
  InvalidX25519EncryptedPayloadError,
  InvalidX25519KeyError,
  PublicKey,
  X25519EncryptedPayload,
  X25519KeyPair,
  X25519PublicKey,
} from '../../src';

const LABEL = 'pigeon-x25519-seal.v1';
const MAX_PLAINTEXT_LENGTH = 64 * 1024;
const EMPTY_ENVELOPE_LENGTH = 106;
const MAX_ENVELOPE_LENGTH = 87488;
const PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const RECIPIENT_PRIVATE = Buffer.from(
  Array.from({ length: 32 }, (_, index) => index + 1),
);
const RECIPIENT_PUBLIC_HEX =
  '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c';
const EPHEMERAL_PRIVATE = Buffer.alloc(32, 0x42);
const NONCE = Buffer.alloc(12, 0x24);
const KNOWN_PLAINTEXT = Buffer.from('pigeon known answer');
const KNOWN_ANSWER =
  'pigeon-x25519-seal.v1.EyxEK-AQ-9V-cmAzKKp25x_MwVA6riGTJ9FNnJmT9HI.JCQkJCQkJCQkJCQk.U8-yBAu9WLeBfwupZvNKiFB_XQ.xqicbHT0oAYa79zAsrXrZg';

const FIELDS: [string, number][] = [
  ['label', 0],
  ['version', 1],
  ['ephemeral key', 2],
  ['nonce', 3],
  ['ciphertext', 4],
  ['tag', 5],
];

const privateKeyObject = (raw: Uint8Array): crypto.KeyObject =>
  crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  });

const publicKeyObject = (raw: Uint8Array): crypto.KeyObject =>
  crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });

const publicBytesOf = (privateKey: crypto.KeyObject): Buffer =>
  crypto
    .createPublicKey(privateKey)
    .export({ format: 'der', type: 'spki' })
    .subarray(-32);

const encode = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64url');

const referenceSeal = (
  recipientPublic: Uint8Array,
  plaintext: Uint8Array,
  ephemeralPrivate: Uint8Array,
  nonce: Uint8Array,
): string => {
  const ephemeral = privateKeyObject(ephemeralPrivate);
  const ephemeralPublic = publicBytesOf(ephemeral);
  const shared = crypto.diffieHellman({
    privateKey: ephemeral,
    publicKey: publicKeyObject(recipientPublic),
  });
  const key = Buffer.from(
    crypto.hkdfSync(
      'sha256',
      shared,
      Buffer.concat([ephemeralPublic, recipientPublic]),
      LABEL,
      32,
    ),
  );
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(Buffer.concat([Buffer.from(LABEL), ephemeralPublic]));
  const cipherText = Buffer.concat([cipher.update(plaintext), cipher.final()]);

  return [
    LABEL,
    encode(ephemeralPublic),
    encode(nonce),
    encode(cipherText),
    encode(cipher.getAuthTag()),
  ].join('.');
};

const referenceOpen = (recipientPrivate: Uint8Array, envelope: string): Buffer => {
  const [, , ephemeral, nonce, cipherText, tag] = envelope.split('.') as [
    string,
    string,
    string,
    string,
    string,
    string,
  ];
  const recipient = privateKeyObject(recipientPrivate);
  const ephemeralPublic = Buffer.from(ephemeral, 'base64url');
  const shared = crypto.diffieHellman({
    privateKey: recipient,
    publicKey: publicKeyObject(ephemeralPublic),
  });
  const key = Buffer.from(
    crypto.hkdfSync(
      'sha256',
      shared,
      Buffer.concat([ephemeralPublic, publicBytesOf(recipient)]),
      LABEL,
      32,
    ),
  );
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(nonce, 'base64url'),
  );
  decipher.setAAD(Buffer.concat([Buffer.from(LABEL), ephemeralPublic]));
  decipher.setAuthTag(Buffer.from(tag, 'base64url'));

  return Buffer.concat([
    decipher.update(Buffer.from(cipherText, 'base64url')),
    decipher.final(),
  ]);
};

const flip = (value: string): string =>
  value.startsWith('A') ? `B${value.slice(1)}` : `A${value.slice(1)}`;

const withPart = (envelope: string, index: number, value: string): string => {
  const parts = envelope.split('.');
  parts[index] = value;

  return parts.join('.');
};

describe('X25519 sealed payloads', () => {
  const recipient = X25519KeyPair.fromPrivateKey(RECIPIENT_PRIVATE);
  const publicKey = recipient.getPublicKey();
  const sealedHello = (): string => publicKey.encrypt('hello').valueOf();

  it('round-trips empty and maximum-size plaintexts', () => {
    const maximum = Buffer.alloc(MAX_PLAINTEXT_LENGTH, 0x5a);

    expect(recipient.decrypt(publicKey.encrypt(Buffer.alloc(0))).length).toBe(
      0,
    );
    expect(recipient.decrypt(publicKey.encrypt(maximum)).equals(maximum)).toBe(
      true,
    );
  });

  it('encrypts Media and Buffer payloads', () => {
    const bytes = Buffer.from('media payload');

    expect(
      recipient.decrypt(publicKey.encrypt(new Media(bytes))).equals(bytes),
    ).toBe(true);
    expect(
      recipient.decrypt(publicKey.encrypt(bytes)).equals(bytes),
    ).toBe(true);
  });

  it('measures 106-character and 87488-character envelopes for 0 and 65536 bytes', () => {
    expect(publicKey.encrypt(Buffer.alloc(0)).valueOf().length).toBe(
      EMPTY_ENVELOPE_LENGTH,
    );
    expect(
      publicKey.encrypt(Buffer.alloc(MAX_PLAINTEXT_LENGTH)).valueOf().length,
    ).toBe(MAX_ENVELOPE_LENGTH);
  });

  it('refuses plaintext above 64 KiB at encrypt time', () => {
    expect(() =>
      publicKey.encrypt(Buffer.alloc(MAX_PLAINTEXT_LENGTH + 1)),
    ).toThrow(InvalidLengthError);
  });

  it('refuses envelopes longer than the serialized maximum', () => {
    expect(() =>
      recipient.decrypt(
        new X25519EncryptedPayload('a'.repeat(MAX_ENVELOPE_LENGTH + 1)),
      ),
    ).toThrow(InvalidX25519EncryptedPayloadError);
  });

  it('refuses non-string payload values', () => {
    expect(() =>
      recipient.decrypt(
        new X25519EncryptedPayload(42 as unknown as string),
      ),
    ).toThrow(InvalidX25519EncryptedPayloadError);
  });

  it('refuses envelopes sealed to another recipient', () => {
    const other = X25519KeyPair.generate();

    expect(() => other.decrypt(publicKey.encrypt('hello'))).toThrow(
      InvalidX25519EncryptedPayloadError,
    );
  });

  it.each(FIELDS)('refuses a modified %s', (_field, index) => {
    const parts = sealedHello().split('.');
    parts[index] = flip(parts[index] as string);

    expect(() =>
      recipient.decrypt(new X25519EncryptedPayload(parts.join('.'))),
    ).toThrow(InvalidX25519EncryptedPayloadError);
  });

  it('refuses a low-order ephemeral key', () => {
    expect(() =>
      recipient.decrypt(
        new X25519EncryptedPayload(
          withPart(sealedHello(), 2, 'A'.repeat(43)),
        ),
      ),
    ).toThrow(InvalidX25519EncryptedPayloadError);
  });

  it.each([2, 3, 4, 5])(
    'refuses a shortened part at index %s',
    (index) => {
      const parts = sealedHello().split('.');
      parts[index] = (parts[index] as string).slice(0, -1);

      expect(() =>
        recipient.decrypt(new X25519EncryptedPayload(parts.join('.'))),
      ).toThrow(InvalidX25519EncryptedPayloadError);
    },
  );

  it.each([
    ['an empty payload', ''],
    ['a label alone', 'pigeon-x25519-seal'],
    ['a missing tag', sealedHello().split('.').slice(0, 5).join('.')],
    ['an appended part', `${sealedHello()}.A`],
  ])('refuses %s', (_name, envelope) => {
    expect(() =>
      recipient.decrypt(new X25519EncryptedPayload(envelope)),
    ).toThrow(InvalidX25519EncryptedPayloadError);
  });

  it('refuses converted-scheme envelopes from PublicKey.encrypt', () => {
    const pair = crypto.generateKeyPairSync('ed25519', {
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' },
    });
    const converted = new PublicKey(pair.publicKey).encrypt('hello');

    expect(() =>
      recipient.decrypt(new X25519EncryptedPayload(converted.valueOf())),
    ).toThrow(InvalidX25519EncryptedPayloadError);
  });

  it('refuses key bytes that are not 32 bytes long', () => {
    expect(() => X25519PublicKey.fromRaw(new Uint8Array(31))).toThrow(
      InvalidX25519KeyError,
    );
    expect(() => X25519KeyPair.fromPrivateKey(new Uint8Array(33))).toThrow(
      InvalidX25519KeyError,
    );
  });

  it('refuses to encrypt to a low-order public key', () => {
    expect(() =>
      X25519PublicKey.fromRaw(new Uint8Array(32)).encrypt('hello'),
    ).toThrow(InvalidX25519KeyError);
  });

  it('derives the public key from the private key', () => {
    expect(Buffer.from(publicKey.toRaw()).toString('hex')).toBe(
      RECIPIENT_PUBLIC_HEX,
    );
  });

  it('copies key bytes on import and export', () => {
    const raw = Buffer.from(RECIPIENT_PRIVATE);
    const pair = X25519KeyPair.fromPrivateKey(raw);
    raw.fill(0);

    expect(
      pair.decrypt(pair.getPublicKey().encrypt('copied')).toString(),
    ).toBe('copied');

    const exported = publicKey.toRaw();
    exported.fill(0);

    expect(publicKey.toRaw().some((byte) => byte !== 0)).toBe(true);
  });

  it('seals the same plaintext to different envelopes', () => {
    expect(sealedHello()).not.toBe(sealedHello());
  });

  it('decrypts envelopes built by an independent node:crypto reference', () => {
    const envelope = referenceSeal(
      publicKey.toRaw(),
      Buffer.from('reference'),
      EPHEMERAL_PRIVATE,
      NONCE,
    );

    expect(recipient.decrypt(new X25519EncryptedPayload(envelope)).toString()).toBe(
      'reference',
    );
  });

  it('produces envelopes that the independent reference opens', () => {
    expect(
      referenceOpen(RECIPIENT_PRIVATE, publicKey.encrypt('forward').valueOf()).toString(),
    ).toBe('forward');
  });

  it('matches the known-answer envelope', () => {
    expect(
      referenceSeal(publicKey.toRaw(), KNOWN_PLAINTEXT, EPHEMERAL_PRIVATE, NONCE),
    ).toBe(KNOWN_ANSWER);
    expect(
      recipient
        .decrypt(new X25519EncryptedPayload(KNOWN_ANSWER))
        .equals(KNOWN_PLAINTEXT),
    ).toBe(true);
  });

  it('exposes domain errors', () => {
    expect(new InvalidX25519KeyError()).toBeInstanceOf(DomainError);
    expect(new InvalidX25519EncryptedPayloadError()).toBeInstanceOf(
      DomainError,
    );
  });
});
