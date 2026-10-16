import { createHash } from 'node:crypto';

import {
  InvalidSignedHttpRequestError,
  KeyPair,
  Signature,
  SignedHttpRequest,
  SignedHttpRequestSignature,
} from '../../src';
import { loadVectors, privateKeyOf, publicKeyOf, VectorKey } from '../vectors';

type RequestInput = {
  body?: Record<string, unknown>;
  bodyBase64?: string;
  bodyText?: string;
  method: string;
  name: string;
  path: string;
  timestamp: number;
};
type Headers = Record<'x-identity-id' | 'x-signature' | 'x-timestamp', string>;
type SignedHttpVectors = {
  cases: {
    derived: {
      canonicalPayload: Record<string, unknown>;
      signature: string;
      signingContent: string;
    };
    headers: Headers;
    input: RequestInput;
    name: string;
  }[];
  key: VectorKey;
  rejected: { headers: Headers; input: RequestInput; name: string }[];
};

const vectors = loadVectors<SignedHttpVectors>('signed-http-request');
const privateKey = privateKeyOf(vectors.key);
const publicKey = publicKeyOf(vectors.key);
const requestOf = (input: RequestInput): SignedHttpRequest => ({
  body:
    input.bodyBase64 === undefined
      ? (input.bodyText ?? input.body)
      : Buffer.from(input.bodyBase64, 'base64'),
  method: input.method,
  path: input.path,
  timestamp: input.timestamp,
});
const request = (overrides: Partial<SignedHttpRequest> = {}) => ({
  method: 'GET',
  path: '/identities/alice',
  timestamp: 1,
  ...overrides,
});
const sha256Hex = (value: string): string =>
  createHash('sha256').update(value).digest('hex');

describe('SignedHttpRequestSignature', () => {
  it.each(vectors.cases)('reproduces $name', ({ derived, headers, input }) => {
    const signed = requestOf(input);

    expect(SignedHttpRequestSignature.payload(signed)).toEqual(
      derived.canonicalPayload,
    );
    expect(SignedHttpRequestSignature.signingContent(signed)).toBe(
      derived.signingContent,
    );
    expect(SignedHttpRequestSignature.sign(signed, privateKey).valueOf()).toBe(
      derived.signature,
    );
    expect(headers['x-identity-id']).toBe(vectors.key.identityId);
    expect(headers['x-timestamp']).toBe(String(input.timestamp));
    expect(() =>
      SignedHttpRequestSignature.verify(
        signed,
        new Signature(headers['x-signature']),
        publicKey,
      ),
    ).not.toThrow();
  });

  it.each(vectors.rejected)('rejects $name', ({ headers, input }) => {
    expect(() =>
      SignedHttpRequestSignature.verify(
        requestOf(input),
        new Signature(headers['x-signature']),
        publicKey,
      ),
    ).toThrow(new InvalidSignedHttpRequestError());
  });

  it('hashes null and absent bodies as an empty JSON object', () => {
    const empty = sha256Hex('{}');

    expect(
      SignedHttpRequestSignature.payload(request({ body: null })).bodyHash,
    ).toBe(empty);
    expect(SignedHttpRequestSignature.payload(request()).bodyHash).toBe(empty);
    expect(
      SignedHttpRequestSignature.payload(request({ body: [1] })).bodyHash,
    ).toBe(sha256Hex('[1]'));
  });

  it('hashes a string body as its raw UTF-8 bytes', () => {
    expect(
      SignedHttpRequestSignature.payload(request({ body: '{"a": 1}' }))
        .bodyHash,
    ).toBe(sha256Hex('{"a": 1}'));
  });

  it('rejects a signature by another key', async () => {
    const other = await KeyPair.generate();
    const signed = request();

    expect(() =>
      SignedHttpRequestSignature.verify(
        signed,
        other.sign(SignedHttpRequestSignature.signingContent(signed)),
        publicKey,
      ),
    ).toThrow(InvalidSignedHttpRequestError);
  });

  it.each([
    ['a non-string method', { method: 1 as unknown as string }],
    ['an unknown method shape', { method: 'GET /' }],
    ['a relative path', { path: 'identities' }],
    ['an empty path', { path: '' }],
    ['an oversized path', { path: `/${'a'.repeat(8192)}` }],
    ['a fractional timestamp', { timestamp: 1.5 }],
    ['a negative timestamp', { timestamp: -1 }],
    ['a numeric body', { body: 1 as unknown as string }],
  ])('rejects %s', (_name, overrides) => {
    expect(() =>
      SignedHttpRequestSignature.signingContent(request(overrides)),
    ).toThrow(new InvalidSignedHttpRequestError());
    expect(() =>
      SignedHttpRequestSignature.sign(request(overrides), privateKey),
    ).toThrow(new InvalidSignedHttpRequestError());
  });

  it('accepts timestamps within the clock skew only', () => {
    const skew = SignedHttpRequestSignature.MAX_CLOCK_SKEW_MS;

    expect(SignedHttpRequestSignature.isFresh(1000, 1000 + skew)).toBeTrue();
    expect(SignedHttpRequestSignature.isFresh(1000 + skew, 1000)).toBeTrue();
    expect(
      SignedHttpRequestSignature.isFresh(1000, 1000 + skew + 1),
    ).toBeFalse();
    expect(SignedHttpRequestSignature.isFresh(Number.NaN, 1000)).toBeFalse();
    expect(SignedHttpRequestSignature.isFresh(1000, 1.5)).toBeFalse();
    expect(SignedHttpRequestSignature.REPLAY_WINDOW_MS).toBe(skew * 2);
  });

  it('keys replay entries by identity and signature', () => {
    const signature = new Signature(vectors.cases[0].derived.signature);

    expect(
      SignedHttpRequestSignature.replayKey(vectors.key.identityId, signature),
    ).toBe(`${vectors.key.identityId}:${signature.valueOf()}`);
  });
});
