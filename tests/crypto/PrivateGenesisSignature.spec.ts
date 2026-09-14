import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';
import canonicalize from 'canonicalize';
import * as Crypto from '../../src';

const nativeKey = createPrivateKey({
  key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.alloc(32, 7),
  ]),
  format: 'der',
  type: 'pkcs8',
});
const publicKey = createPublicKey(nativeKey);
const owner = publicKey
  .export({ format: 'der', type: 'spki' })
  .subarray(-32)
  .toString('base64url');
const key = Crypto.PrivateKey.fromPEM(
  nativeKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
);
const encoded = (byte: number) => Buffer.alloc(32, byte).toString('base64url');
const hash = (value: unknown) =>
  createHash('sha256').update(canonicalize(value)!).digest('base64url');
const genesis = () => {
  const policy = {
    version: 1,
    devices: [{ deviceKey: owner, mlsCredentialHash: encoded(4) }],
    authorityKeys: [owner],
    threshold: 1,
    sequencerKey: owner,
    freshnessAuthorityKey: owner,
    leaseRevocationKey: owner,
    leaseRevocationHpkeKey: encoded(5),
  };
  const head = {
    scopeId: encoded(1),
    revision: 0,
    parentHeadHash: null,
    mlsEpoch: 0,
    mlsContextHash: encoded(2),
    policyHash: hash(policy),
  };
  return { version: 1, ...head, headHash: hash(head), policy };
};
const nativeSigned = (value: object, domain = 'pigeon.private-genesis.v1') =>
  JSON.stringify({
    ...value,
    signatures: {
      [owner]: sign(
        null,
        Buffer.from(domain + '\0' + canonicalize(value)),
        nativeKey,
      ).toString('base64url'),
    },
  });
const api = Crypto.PrivateGenesisSignature;
const accept = (json: string) =>
  api.verify(json, owner, encoded(1), encoded(2));

describe('PrivateGenesisSignature', () => {
  it('exports an authenticated genesis boundary', () => {
    expect(api).toBeDefined();
  });

  it('accepts an independently signed genesis only for the pinned scope, owner and MLS context', () => {
    const value = genesis();
    const signed = nativeSigned(value);
    expect(accept(signed)).toBe(canonicalize(JSON.parse(signed)));
    const locallySigned = api.sign(JSON.stringify(value), key);
    expect(locallySigned).toBe(accept(signed));
    const parsed = JSON.parse(locallySigned);
    expect(
      verify(
        null,
        Buffer.from('pigeon.private-genesis.v1\0' + canonicalize(value)),
        publicKey,
        Buffer.from(parsed.signatures[owner], 'base64url'),
      ),
    ).toBe(true);
  });

  it.each(['owner', 'scope', 'context'])(
    'rejects an independently valid record with the wrong pinned %s',
    (pin) => {
      expect(() =>
        api.verify(
          nativeSigned(genesis()),
          pin === 'owner' ? encoded(8) : owner,
          pin === 'scope' ? encoded(8) : encoded(1),
          pin === 'context' ? encoded(8) : encoded(2),
        ),
      ).toThrow('Invalid private genesis');
    },
  );

  it.each([
    { version: 2 },
    { revision: 1 },
    { mlsEpoch: 1 },
    { parentHeadHash: encoded(9) },
    { scopeId: 'invalid' },
    { mlsContextHash: 'invalid' },
    { policyHash: encoded(8) },
    { headHash: encoded(8) },
    { extra: true },
    { version: undefined },
  ])('rejects signed invalid genesis fields %j', (change) => {
    const candidate = { ...genesis(), ...change };
    if (
      ['revision', 'mlsEpoch', 'parentHeadHash'].some((field) =>
        Object.hasOwn(change, field),
      )
    ) {
      candidate.headHash = hash({
        scopeId: candidate.scopeId,
        revision: candidate.revision,
        parentHeadHash: candidate.parentHeadHash,
        mlsEpoch: candidate.mlsEpoch,
        mlsContextHash: candidate.mlsContextHash,
        policyHash: candidate.policyHash,
      });
    }
    expect(() => accept(nativeSigned(candidate))).toThrow(
      'Invalid private genesis',
    );
  });

  it.each([
    null,
    [],
    'invalid',
    { version: 2 },
    { devices: [] },
    { devices: null },
    { devices: [null] },
    { devices: [{ deviceKey: owner }] },
    { devices: [{ deviceKey: owner, mlsCredentialHash: 'invalid' }] },
    { devices: [{ deviceKey: encoded(9), mlsCredentialHash: encoded(4) }] },
    {
      devices: [
        { deviceKey: owner, mlsCredentialHash: encoded(4) },
        { deviceKey: encoded(9), mlsCredentialHash: encoded(4) },
      ],
    },
    { authorityKeys: null },
    { authorityKeys: [] },
    { authorityKeys: [owner, encoded(9)] },
    { authorityKeys: [encoded(9)] },
    { threshold: 2 },
    { sequencerKey: encoded(9) },
    { freshnessAuthorityKey: encoded(9) },
    { leaseRevocationKey: encoded(9) },
    { leaseRevocationHpkeKey: owner },
    { leaseRevocationHpkeKey: 'invalid' },
    { extra: true },
  ])(
    'rejects an owner-signed invalid or prepopulated genesis policy %j',
    (change) => {
      const value = genesis();
      const policy =
        change && typeof change === 'object' && !Array.isArray(change)
          ? { ...value.policy, ...change }
          : change;
      const policyHash = hash(policy);
      const head = {
        scopeId: value.scopeId,
        revision: 0,
        parentHeadHash: null,
        mlsEpoch: 0,
        mlsContextHash: value.mlsContextHash,
        policyHash,
      };
      expect(() =>
        accept(
          nativeSigned({ ...value, policy, policyHash, headHash: hash(head) }),
        ),
      ).toThrow('Invalid private genesis');
    },
  );

  it.each([
    {},
    null,
    [],
    { [owner]: 'bad' },
    { [encoded(9)]: encoded(1) },
    { [owner]: 'A'.repeat(86), [encoded(9)]: 'A'.repeat(86) },
  ])('rejects invalid signature maps %j', (signatures) => {
    expect(() => accept(JSON.stringify({ ...genesis(), signatures }))).toThrow(
      'Invalid private genesis',
    );
  });

  it('rejects signature tampering and cross-protocol replay', () => {
    expect(() =>
      accept(nativeSigned(genesis(), 'pigeon.private-control.v1')),
    ).toThrow('Invalid private genesis');
    expect(() =>
      accept(
        JSON.stringify({
          ...genesis(),
          signatures: { [owner]: Buffer.alloc(64).toString('base64url') },
        }),
      ),
    ).toThrow('Invalid private genesis');
  });

  it('rejects duplicate JSON keys and does not expose input in errors', () => {
    const input = nativeSigned(genesis()).replace(
      '"version":1',
      '"version":2,"version":1',
    );
    expect(() => accept(input)).toThrow('Invalid private genesis');
    expect(() => api.sign('{"secret":"DO-NOT-LOG"}', key)).toThrow(
      'Invalid private genesis',
    );
    try {
      accept('{"secret":"DO-NOT-LOG"}');
    } catch (error) {
      expect(String(error)).toBe(
        'InvalidPrivateGenesisError: Invalid private genesis',
      );
      expect((error as Error).cause).toBeUndefined();
    }
  });

  it('refuses to sign for a different genesis owner', () => {
    expect(() =>
      api.sign(JSON.stringify(genesis()), Crypto.PrivateKey.generate()),
    ).toThrow('Invalid private genesis');
  });
});
