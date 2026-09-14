import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
} from 'node:crypto';
import canonicalize from 'canonicalize';
import * as Crypto from '../../src';

const key = (byte: number) =>
  createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b657004220420', 'hex'),
      Buffer.alloc(32, byte),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
const keys = [key(7), key(8), key(9)];
const owners = keys.map((key) =>
  createPublicKey(key)
    .export({ format: 'der', type: 'spki' })
    .subarray(-32)
    .toString('base64url'),
);
const encoded = (byte: number) => Buffer.alloc(32, byte).toString('base64url');
const hash = (value: unknown) =>
  createHash('sha256').update(canonicalize(value)!).digest('base64url');
const policy = () => ({
  version: 1,
  devices: owners.map((deviceKey, i) => ({
    deviceKey,
    mlsCredentialHash: encoded(i + 20),
  })),
  authorityKeys: owners,
  threshold: 2,
  sequencerKey: owners[0],
  freshnessAuthorityKey: owners[1],
  leaseRevocationKey: owners[0],
  leaseRevocationHpkeKey: encoded(5),
});
const checkpoint = () => ({
  scopeId: encoded(1),
  revision: 3,
  headHash: encoded(2),
  mlsEpoch: 3,
  policy: policy(),
});
const control = (change: Record<string, unknown> = {}) => {
  const previous = checkpoint();
  const head = {
    scopeId: previous.scopeId,
    revision: 4,
    parentHeadHash: previous.headHash,
    mlsEpoch: 4,
    mlsContextHash: encoded(3),
    policyHash: hash(policy()),
  };
  const value = {
    ...head,
    headHash: hash(head),
    mlsMessageHash: encoded(4),
    policy: policy(),
    ...change,
  };
  value.policyHash = hash(value.policy);
  value.headHash = hash(
    Object.fromEntries(
      Object.keys(head).map((name) => [
        name,
        value[name as keyof typeof value],
      ]),
    ),
  );
  return value;
};
const signed = (
  value: object,
  signers = [0, 1],
  domain = 'pigeon.private-control.v1',
) =>
  JSON.stringify({
    ...value,
    signatures: Object.fromEntries(
      signers.map((i) => [
        owners[i],
        sign(
          null,
          Buffer.from(domain + '\0' + canonicalize(value)),
          keys[i],
        ).toString('base64url'),
      ]),
    ),
  });
const api = Crypto.PrivateControlSignature;
const accept = (json: string, previous: object = checkpoint()) =>
  api.verify(json, JSON.stringify(previous), encoded(4), encoded(3));

describe('PrivateControlSignature', () => {
  it('exports the control verification boundary', () =>
    expect(api).toBeDefined());
  it('authenticates before MLS processing and requires the actual final context before adoption', () => {
    const input = signed(control());
    expect(
      api.authenticate(input, JSON.stringify(checkpoint()), encoded(4)),
    ).toBe(canonicalize(JSON.parse(input)));
    expect(() =>
      api.verify(input, JSON.stringify(checkpoint()), encoded(4), encoded(9)),
    ).toThrow('Invalid private control');
  });
  it('accepts a native-signed previous quorum including the previous sequencer', () => {
    const input = signed(control());
    expect(accept(input)).toBe(canonicalize(JSON.parse(input)));
  });
  it('accepts replacement of administrators only when the previous authorities sign', () => {
    const nextPolicy = {
      ...policy(),
      authorityKeys: [owners[2]],
      threshold: 1,
      sequencerKey: owners[2],
    };
    const input = signed(control({ policy: nextPolicy }));
    expect(accept(input)).toBe(canonicalize(JSON.parse(input)));
    expect(() => accept(signed(control({ policy: nextPolicy }), [2]))).toThrow(
      'Invalid private control',
    );
  });
  it.each([[0], [1, 2], []])(
    'rejects insufficient quorum or missing sequencer %j',
    (...signers) => {
      expect(() => accept(signed(control(), signers))).toThrow(
        'Invalid private control',
      );
    },
  );
  it.each([
    { scopeId: encoded(9) },
    { parentHeadHash: encoded(9) },
    { revision: 3 },
    { revision: 5 },
    { revision: 4.5 },
    { revision: -1 },
    { mlsEpoch: 3 },
    { mlsEpoch: 5 },
    { mlsMessageHash: encoded(9) },
    { mlsContextHash: encoded(9) },
    { extra: true },
  ])('rejects signed and rehashed wrong transition %j', (change) => {
    expect(() => accept(signed(control(change)))).toThrow(
      'Invalid private control',
    );
  });
  it.each([
    { version: 2 },
    { devices: [] },
    { devices: null },
    {
      devices: [
        { deviceKey: owners[0], mlsCredentialHash: encoded(20) },
        { deviceKey: owners[0], mlsCredentialHash: encoded(21) },
      ],
    },
    {
      devices: [
        { deviceKey: owners[0], mlsCredentialHash: encoded(20) },
        { deviceKey: owners[1], mlsCredentialHash: encoded(20) },
      ],
    },
    { authorityKeys: [] },
    { authorityKeys: [owners[0], owners[0]] },
    { authorityKeys: [encoded(9)] },
    { threshold: 0 },
    { threshold: 4 },
    { threshold: 1.5 },
    { sequencerKey: encoded(9) },
    { freshnessAuthorityKey: encoded(9) },
    { leaseRevocationKey: owners[1] },
    { leaseRevocationHpkeKey: encoded(9) },
    { extra: true },
  ])('rejects signed and rehashed invalid candidate policy %j', (change) => {
    expect(() =>
      accept(signed(control({ policy: { ...policy(), ...change } }))),
    ).toThrow('Invalid private control');
  });
  it('rejects unknown signers even alongside a valid quorum', () => {
    const value = JSON.parse(signed(control()));
    value.signatures[encoded(9)] = 'A'.repeat(86);
    expect(() => accept(JSON.stringify(value))).toThrow(
      'Invalid private control',
    );
  });
  it('rejects tampering, incorrect domain and duplicate signer keys', () => {
    const value = JSON.parse(signed(control()));
    value.signatures[owners[0]] = Buffer.alloc(64).toString('base64url');
    expect(() => accept(JSON.stringify(value))).toThrow(
      'Invalid private control',
    );
    expect(() =>
      accept(signed(control(), [0, 1], 'pigeon.private-genesis.v1')),
    ).toThrow('Invalid private control');
    const input = signed(control()).replace(
      '"signatures":{',
      '"signatures":{"' + owners[0] + '":"ignored",',
    );
    expect(() => accept(input)).toThrow('Invalid private control');
  });
  it('rejects inconsistent hashes despite valid signatures', () => {
    expect(() =>
      accept(signed({ ...control(), headHash: encoded(9) })),
    ).toThrow('Invalid private control');
    expect(() =>
      accept(signed({ ...control(), policyHash: encoded(9) })),
    ).toThrow('Invalid private control');
  });
  it('rejects an invalid extra admitted signature even when other signatures satisfy the quorum', () => {
    const input = signed(control(), [0, 1, 2]);
    expect(accept(input)).toBe(canonicalize(JSON.parse(input)));
    const value = JSON.parse(input);
    value.signatures[owners[2]] = Buffer.alloc(64).toString('base64url');
    expect(() => accept(JSON.stringify(value))).toThrow(
      'Invalid private control',
    );
  });
  it.each([null, [], 'invalid'])(
    'rejects malformed signature maps %j',
    (signatures) => {
      expect(() =>
        accept(JSON.stringify({ ...control(), signatures })),
      ).toThrow('Invalid private control');
    },
  );
  it.each([
    { scopeId: 'invalid' },
    { revision: -1 },
    { revision: 3.5 },
    { mlsEpoch: -1 },
    { revision: Number.MAX_SAFE_INTEGER },
    { headHash: 'invalid' },
    { extra: true },
    { policy: null },
    { policy: { ...policy(), threshold: 4 } },
  ])('rejects corrupt trusted checkpoints %j', (change) => {
    expect(() =>
      accept(signed(control()), { ...checkpoint(), ...change }),
    ).toThrow('Invalid private control');
  });
  it('never returns submitted data in errors', () => {
    expect(() => accept('{"secret":"DO-NOT-LOG"}')).toThrow(
      Crypto.InvalidPrivateControlError,
    );
    try {
      accept('{"secret":"DO-NOT-LOG"}');
    } catch (error) {
      expect(String(error)).toBe(
        'InvalidPrivateControlError: Invalid private control',
      );
      expect((error as Error).cause).toBeUndefined();
    }
  });
  it('supports the full 128-device quorum without duplicate identities', () => {
    const allKeys = Array.from({ length: 128 }, (_, i) => key(i));
    const allOwners = allKeys.map((key) =>
      createPublicKey(key)
        .export({ format: 'der', type: 'spki' })
        .subarray(-32)
        .toString('base64url'),
    );
    const fullPolicy = {
      ...policy(),
      devices: allOwners.map((deviceKey, i) => ({
        deviceKey,
        mlsCredentialHash: encoded(i),
      })),
      authorityKeys: allOwners,
      threshold: 128,
      sequencerKey: allOwners[0],
      freshnessAuthorityKey: allOwners[1],
    };
    const value = control({ policy: fullPolicy });
    const bytes = Buffer.from(
      'pigeon.private-control.v1\0' + canonicalize(value),
    );
    const input = JSON.stringify({
      ...value,
      signatures: Object.fromEntries(
        allKeys.map((key, i) => [
          allOwners[i],
          sign(null, bytes, key).toString('base64url'),
        ]),
      ),
    });
    expect(accept(input, { ...checkpoint(), policy: fullPolicy })).toBe(
      canonicalize(JSON.parse(input)),
    );
    expect(() =>
      accept(
        signed(
          control({
            policy: {
              ...fullPolicy,
              devices: [...fullPolicy.devices, fullPolicy.devices[0]],
            },
          }),
        ),
      ),
    ).toThrow('Invalid private control');
  });
});
