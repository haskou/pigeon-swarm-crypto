import {
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import canonicalize from 'canonicalize';

import * as Crypto from '../../src';
import { PrivateKey } from '../../src/PrivateKey';

const seed = Buffer.alloc(32, 17);
const privateDer = Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'),
  seed,
]);
const nodePrivate = createPrivateKey({
  key: privateDer,
  format: 'der',
  type: 'pkcs8',
});
const nodePublic = createPublicKey(nodePrivate);
const signerKey = nodePublic
  .export({ format: 'der', type: 'spki' })
  .subarray(-32)
  .toString('base64url');
const privateKey = PrivateKey.fromPEM(
  nodePrivate.export({ format: 'pem', type: 'pkcs8' }).toString(),
);
const encoded = (byte: number): string =>
  Buffer.alloc(32, byte).toString('base64url');
const request = () => ({
  version: 1,
  scopeId: encoded(1),
  nonce: encoded(2),
  expectedRevision: 7,
  expectedHeadHash: encoded(3),
  batchCommitment: encoded(4),
});
const proof = () => ({
  version: 1,
  scopeId: encoded(1),
  nonce: encoded(2),
  revision: 7,
  headHash: encoded(3),
  batchCommitment: encoded(4),
  signerKey,
});

describe('PrivateFreshnessProof', () => {
  const api = Crypto.PrivateFreshnessProof;

  it('signs canonical proof bytes and verifies them against the exact request', () => {
    const signed = api.sign(JSON.stringify(proof()), privateKey);
    const parsed = JSON.parse(signed);
    const unsigned = { ...parsed };
    delete unsigned.signature;

    expect(
      verify(
        null,
        Buffer.from(
          'pigeon.private-freshness.v1\0' + canonicalize(unsigned),
        ),
        nodePublic,
        Buffer.from(parsed.signature, 'base64url'),
      ),
    ).toBe(true);
    expect(api.verify(signed, signerKey, JSON.stringify(request()))).toBe(
      canonicalize(parsed),
    );
  });

  it('verifies an independently generated signature with reordered fields', () => {
    const signature = sign(
      null,
      Buffer.from('pigeon.private-freshness.v1\0' + canonicalize(proof())),
      nodePrivate,
    ).toString('base64url');
    const input = JSON.stringify({
      signature,
      ...Object.fromEntries(Object.entries(proof()).reverse()),
    });

    expect(api.verify(input, signerKey, JSON.stringify(request()))).toBe(
      canonicalize({ ...proof(), signature }),
    );
  });

  it.each([
    ['scopeId', encoded(9)],
    ['nonce', encoded(9)],
    ['revision', 8],
    ['headHash', encoded(9)],
    ['batchCommitment', encoded(9)],
  ])('rejects proof %s that does not match the request', (field, value) => {
    const signed = api.sign(
      JSON.stringify({ ...proof(), [field]: value }),
      privateKey,
    );

    expect(() =>
      api.verify(signed, signerKey, JSON.stringify(request())),
    ).toThrow('Invalid private freshness proof');
  });

  it('rejects a valid self-signature when the expected signer differs', () => {
    const signed = api.sign(JSON.stringify(proof()), privateKey);

    expect(() =>
      api.verify(signed, encoded(9), JSON.stringify(request())),
    ).toThrow('Invalid private freshness proof');
  });

  it('refuses to sign a proof that names another authority key', () => {
    expect(() =>
      api.sign(
        JSON.stringify({ ...proof(), signerKey: encoded(9) }),
        privateKey,
      ),
    ).toThrow('Invalid private freshness proof');
  });

  it.each([
    { version: 2 },
    { revision: -1 },
    { revision: 1.5 },
    { revision: Number.MAX_SAFE_INTEGER + 1 },
    { scopeId: 'invalid' },
    { scopeId: 1 },
    { nonce: 'invalid' },
    { headHash: 'invalid' },
    { batchCommitment: 'invalid' },
    { signerKey: 'invalid' },
    { extra: true },
    { nonce: undefined },
    { nonce: undefined, wrongNonce: encoded(2) },
  ])('rejects invalid proof shape %j', (change) => {
    expect(() =>
      api.sign(JSON.stringify({ ...proof(), ...change }), privateKey),
    ).toThrow('Invalid private freshness proof');
  });

  it.each([
    { version: 2 },
    { expectedRevision: -1 },
    { expectedRevision: 1.5 },
    { expectedRevision: Number.MAX_SAFE_INTEGER + 1 },
    { scopeId: 'invalid' },
    { scopeId: 1 },
    { nonce: 'invalid' },
    { expectedHeadHash: 'invalid' },
    { batchCommitment: 'invalid' },
    { extra: true },
    { nonce: undefined },
    { nonce: undefined, wrongNonce: encoded(2) },
  ])('rejects invalid request shape %j', (change) => {
    const signed = api.sign(JSON.stringify(proof()), privateKey);

    expect(() =>
      api.verify(
        signed,
        signerKey,
        JSON.stringify({ ...request(), ...change }),
      ),
    ).toThrow('Invalid private freshness proof');
  });

  it('rejects duplicate properties before JSON parsing can conceal them', () => {
    const signed = api.sign(JSON.stringify(proof()), privateKey);
    const duplicateProof = signed.replace(
      '"version":1',
      '"version":2,"version":1',
    );
    const duplicateRequest = JSON.stringify(request()).replace(
      '"version":1',
      '"version":2,"version":1',
    );

    expect(() =>
      api.verify(duplicateProof, signerKey, JSON.stringify(request())),
    ).toThrow('Invalid private freshness proof');
    expect(() => api.verify(signed, signerKey, duplicateRequest)).toThrow(
      'Invalid private freshness proof',
    );
  });

  it.each([
    { signature: Buffer.alloc(64).toString('base64url') },
    { signature: 'invalid' },
    { signature: 1 },
    { signerKey: encoded(9) },
    { extra: true },
    { signature: undefined },
  ])('rejects tampered or extended signed proof %j', (change) => {
    const signed = JSON.parse(api.sign(JSON.stringify(proof()), privateKey));

    expect(() =>
      api.verify(
        JSON.stringify({ ...signed, ...change }),
        signerKey,
        JSON.stringify(request()),
      ),
    ).toThrow('Invalid private freshness proof');
  });

  it('rejects a signature from another protocol domain', () => {
    const signature = sign(
      null,
      Buffer.from('pigeon.private-operation.v1\0' + canonicalize(proof())),
      nodePrivate,
    ).toString('base64url');

    expect(() =>
      api.verify(
        JSON.stringify({ ...proof(), signature }),
        signerKey,
        JSON.stringify(request()),
      ),
    ).toThrow('Invalid private freshness proof');
  });

  it('returns one fixed error without submitted values or causes', () => {
    try {
      api.verify(
        '{"secret":"DO-NOT-LOG"}',
        signerKey,
        JSON.stringify(request()),
      );
      throw new Error('Expected verification to fail');
    } catch (error) {
      expect(String(error)).toBe(
        'InvalidPrivateFreshnessProofError: Invalid private freshness proof',
      );
      expect(JSON.stringify(error)).not.toContain('DO-NOT-LOG');
      expect((error as Error).cause).toBeUndefined();
    }
  });
});
