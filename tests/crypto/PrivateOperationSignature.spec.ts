import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { PrivateKey } from '../../src/PrivateKey';
import { PrivateOperationSignature } from '../../src/PrivateOperationSignature';

const seed = Buffer.alloc(32, 7);
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
const author = nodePublic
  .export({ format: 'der', type: 'spki' })
  .subarray(-32)
  .toString('base64url');
const key = PrivateKey.fromPEM(
  nodePrivate.export({ format: 'pem', type: 'pkcs8' }).toString(),
);
const operation = () => ({
  version: 1,
  operationId: Buffer.alloc(16, 1).toString('base64url'),
  scopeId: Buffer.alloc(32, 2).toString('base64url'),
  authorizationRevision: 0,
  authorDeviceKey: author,
  kind: 'message.create',
  previousOperationIds: [],
  payload: { text: 'private text' },
});

describe('PrivateOperationSignature', () => {
  it('signs deterministic canonical bytes verified by Node crypto', () => {
    const signed = PrivateOperationSignature.sign(
      JSON.stringify(operation()),
      key,
    );
    const parsed = JSON.parse(signed);
    const expected =
      '{"authorDeviceKey":"' +
      author +
      '","authorizationRevision":0,"kind":"message.create","operationId":"AQEBAQEBAQEBAQEBAQEBAQ","payload":{"text":"private text"},"previousOperationIds":[],"scopeId":"AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI","version":1}';
    expect(
      verify(
        null,
        Buffer.from('pigeon.private-operation.v1\0' + expected),
        nodePublic,
        Buffer.from(parsed.signature, 'base64url'),
      ),
    ).toBe(true);
    expect(PrivateOperationSignature.verify(signed, author)).toBe(signed);
  });

  it('rejects a duplicate property before JSON parsing can conceal it', () => {
    const input = JSON.stringify(operation()).replace(
      '"version":1',
      '"version":2,"version":1',
    );
    expect(() => PrivateOperationSignature.sign(input, key)).toThrow(
      'Invalid private operation',
    );
  });

  it('rejects a valid self-signature when the expected device is different', () => {
    const signed = PrivateOperationSignature.sign(
      JSON.stringify(operation()),
      key,
    );
    expect(() =>
      PrivateOperationSignature.verify(
        signed,
        Buffer.alloc(32, 4).toString('base64url'),
      ),
    ).toThrow('Invalid private operation');
  });
});

describe('private operation rejection boundary', () => {
  const signed = () =>
    PrivateOperationSignature.sign(JSON.stringify(operation()), key);
  it.each([
    { version: 2 },
    { version: '1' },
    { kind: 'admin.grant' },
    { authorizationRevision: -1 },
    { authorizationRevision: 1.5 },
    { authorizationRevision: Number.MAX_SAFE_INTEGER + 1 },
    { payload: null },
    { payload: [] },
    { payload: 'text' },
    { operationId: 'A' },
    { operationId: 1 },
    { scopeId: 'A'.repeat(43) + '=' },
    { authorDeviceKey: Buffer.alloc(32, 8).toString('base64url') },
    { previousOperationIds: null },
    { previousOperationIds: Array(33).fill('A'.repeat(22)) },
    { previousOperationIds: ['A'.repeat(22), 'A'.repeat(22)] },
    { previousOperationIds: ['invalid'] },
    { operationId: 'A'.repeat(21) + 'B' },
    { extra: true },
    { version: undefined },
  ])('rejects invalid unsigned shape %j', (change) => {
    expect(() =>
      PrivateOperationSignature.sign(
        JSON.stringify({ ...operation(), ...change }),
        key,
      ),
    ).toThrow('Invalid private operation');
  });

  it.each([
    '',
    'null',
    '[]',
    '{}',
    '{',
    '{"x":1,}',
    '{/* comment */"x":1}',
    '{"x":1,"\\u0078":2}',
    '{"x":{"a":1,"a":2}}',
    '{"x":1e400}',
    '{"x":"\\ud800"}',
    '{"\\udfff":1}',
    ' '.repeat(262145),
    '{"x":"' + '😀'.repeat(70000) + '"}',
    '{"x":' + '['.repeat(33) + '0' + ']'.repeat(33) + '}',
    '{"x":[' + Array(5000).fill('0').join(',') + ']}',
  ])('rejects malformed or resource-exhausting JSON (case %#)', (input) => {
    expect(() => PrivateOperationSignature.sign(input, key)).toThrow(
      'Invalid private operation',
    );
  });

  it.each([
    { signature: 'A'.repeat(86) },
    { signature: 'A'.repeat(85) + 'B' },
    { scopeId: Buffer.alloc(32, 3).toString('base64url') },
    { operationId: Buffer.alloc(16, 3).toString('base64url') },
    { authorizationRevision: 1 },
    { payload: { text: 'tampered' } },
    { kind: 'message.delete' },
    { previousOperationIds: [Buffer.alloc(16, 5).toString('base64url')] },
    { signature: undefined },
    { version: 2 },
  ])('rejects tampered signed operations %j', (change) => {
    expect(() =>
      PrivateOperationSignature.verify(
        JSON.stringify({ ...JSON.parse(signed()), ...change }),
        author,
      ),
    ).toThrow('Invalid private operation');
  });

  it('rejects a valid signature under a different protocol domain', () => {
    const parsed = JSON.parse(signed());
    delete parsed.signature;
    const bytes = JSON.stringify(parsed);
    const signature = sign(
      null,
      Buffer.from('pigeon.private-control.v1\0' + bytes),
      nodePrivate,
    ).toString('base64url');
    expect(() =>
      PrivateOperationSignature.verify(
        JSON.stringify({ ...parsed, signature }),
        author,
      ),
    ).toThrow('Invalid private operation');
  });

  it('verifies an independently generated Node signature with reordered keys', () => {
    const parsed = JSON.parse(signed());
    delete parsed.signature;
    const signature = sign(
      null,
      Buffer.from('pigeon.private-operation.v1\0' + JSON.stringify(parsed)),
      nodePrivate,
    ).toString('base64url');
    const reordered = {
      signature,
      ...Object.fromEntries(Object.entries(parsed).reverse()),
    };
    expect(
      PrivateOperationSignature.verify(
        JSON.stringify(reordered, null, 2),
        author,
      ),
    ).toBe(signed());
  });

  it('preserves Unicode, nested property ordering, arrays and valid causal links', () => {
    const input = {
      ...operation(),
      previousOperationIds: [Buffer.alloc(16, 3).toString('base64url')],
      payload: { z: [null, true, 1e30, { z: '😀', a: 'é' }], a: -0 },
    };
    const result = PrivateOperationSignature.sign(JSON.stringify(input), key);
    expect(result).toContain(
      '"payload":{"a":0,"z":[null,true,1e+30,{"a":"é","z":"😀"}]}',
    );
    expect(PrivateOperationSignature.verify(result, author)).toBe(result);
  });

  it('does not leak submitted content or keys through failures', () => {
    try {
      PrivateOperationSignature.sign('{"secret":"DO-NOT-LOG",}', key);
    } catch (error) {
      expect(String(error)).toBe(
        'InvalidPrivateOperationError: Invalid private operation',
      );
      expect(JSON.stringify(error)).not.toContain('DO-NOT-LOG');
      expect((error as Error).cause).toBeUndefined();
    }
  });

  it('bounds the resulting signed representation as well as input', () => {
    const value = operation();
    value.payload.text = '';
    value.payload.text = 'a'.repeat(262144 - JSON.stringify(value).length);
    expect(Buffer.byteLength(JSON.stringify(value))).toBe(262144);
    expect(() =>
      PrivateOperationSignature.sign(JSON.stringify(value), key),
    ).toThrow('Invalid private operation');
  });

  it('rejects malformed expected public keys', () => {
    expect(() => PrivateOperationSignature.verify(signed(), 'bad')).toThrow(
      'Invalid private operation',
    );
  });
});

it('rejects a small-order Ed25519 public key and signature', () => {
  const identityPoint = Buffer.alloc(32);
  identityPoint[0] = 1;
  const weakAuthor = identityPoint.toString('base64url');
  const signature = Buffer.concat([identityPoint, Buffer.alloc(32)]).toString(
    'base64url',
  );
  const forged = JSON.stringify({
    ...operation(),
    authorDeviceKey: weakAuthor,
    signature,
  });
  expect(() => PrivateOperationSignature.verify(forged, weakAuthor)).toThrow(
    'Invalid private operation',
  );
});
