import { CanonicalJson, InvalidCanonicalJsonError } from '../../src';
import { loadVectors } from '../vectors';

type CanonicalJsonVectors = {
  cases: { canonical: string; name: string; value: unknown }[];
  rejectedJson: { json: string; name: string }[];
};

const vectors = loadVectors<CanonicalJsonVectors>('canonical-json');

describe('CanonicalJson', () => {
  it.each(vectors.cases)('serializes $name', ({ canonical, value }) => {
    expect(CanonicalJson.serialize(value)).toBe(canonical);
  });

  it.each(vectors.rejectedJson)('rejects $name', ({ json }) => {
    expect(() => CanonicalJson.serialize(JSON.parse(json))).toThrow(
      InvalidCanonicalJsonError,
    );
  });

  it('omits undefined members and accepts null-prototype objects', () => {
    const record = Object.assign(Object.create(null) as object, { b: 1 });

    expect(CanonicalJson.serialize({ a: undefined, record })).toBe(
      '{"record":{"b":1}}',
    );
  });
  it('keeps a __proto__ member as an ordinary member', () => {
    expect(CanonicalJson.serialize(JSON.parse('{"__proto__":1,"a":2}'))).toBe(
      '{"__proto__":1,"a":2}',
    );
  });

  it('accepts exactly the maximum nesting depth', () => {
    let value: unknown = [];

    for (let depth = 1; depth < CanonicalJson.MAX_DEPTH; depth += 1)
      value = [value];

    expect(CanonicalJson.serialize(value)).toHaveLength(
      CanonicalJson.MAX_DEPTH * 2,
    );
  });

  it.each([
    ['an undefined array item', [undefined]],
    ['an array hole', new Array(1)],
    ['a top-level undefined', undefined],
    ['a non-finite number', Number.NaN],
    ['a bigint', BigInt(1)],
    ['a function', () => 1],
    ['a symbol', Symbol('value')],
    ['a class instance', new Date(0)],
    ['a map', new Map()],
    ['a byte array', new Uint8Array(1)],
  ])('rejects %s', (_name, value) => {
    expect(() => CanonicalJson.serialize(value)).toThrow(
      new InvalidCanonicalJsonError(),
    );
  });
});
