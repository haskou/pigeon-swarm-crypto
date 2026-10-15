import { createHash } from 'node:crypto';

import { BearerCapability, InvalidBearerCapabilityError } from '../../src';
import vectors from '../../vectors/bearer-capabilities.json';

describe('BearerCapability shipped vectors', () => {
  it.each(vectors.hash.valid.map((item) => [item.name, item] as const))(
    'hashes the %s',
    (_name, item) => {
      expect(BearerCapability.hash(item.token)).toBe(item.hash);
      expect(
        createHash('sha256').update(item.token, 'utf8').digest('hex'),
      ).toBe(item.hash);
    },
  );

  it.each(vectors.hash.invalid.map((item) => [item.name, item.token] as const))(
    'refuses to hash a token with %s',
    (_name, token) => {
      expect(() => BearerCapability.hash(token)).toThrow(
        InvalidBearerCapabilityError,
      );
    },
  );

  it.each(vectors.verify.map((item) => [item.name, item] as const))(
    'verifies %s',
    (_name, item) => {
      expect(BearerCapability.verify(item.token, item.hash)).toBe(
        item.expected,
      );
    },
  );

  it('rejects inputs that are not strings', () => {
    const [{ hash, token }] = vectors.hash.valid;

    expect(() => BearerCapability.hash(7 as never)).toThrow(
      InvalidBearerCapabilityError,
    );
    expect(BearerCapability.verify(7, hash)).toBeFalse();
    expect(BearerCapability.verify(token, undefined)).toBeFalse();
  });

  it('generates 256-bit tokens with their commitment', () => {
    const first = BearerCapability.generate();
    const second = BearerCapability.generate();

    expect(first.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Buffer.from(first.token, 'base64url')).toHaveLength(32);
    expect(first.hash).toBe(BearerCapability.hash(first.token));
    expect(BearerCapability.verify(first.token, first.hash)).toBeTrue();
    expect(second.token).not.toBe(first.token);
  });

  it('never echoes the input in the error', () => {
    const error = new InvalidBearerCapabilityError();

    expect(error.message).toBe('Invalid bearer capability');
    expect(error.name).toBe('InvalidBearerCapabilityError');
  });
});
