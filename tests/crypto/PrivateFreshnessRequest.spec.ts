import {
  InvalidPrivateFreshnessRequestError,
  PrivateFreshnessRequest,
  type PrivateFreshnessRequestInput,
} from '../../src';
import { loadVectors } from '../vectors';

type FreshnessRequestVectors = {
  cases: {
    input: PrivateFreshnessRequestInput;
    name: string;
    requestJson: string;
  }[];
  rejected: { input: PrivateFreshnessRequestInput; name: string }[];
};

const vectors = loadVectors<FreshnessRequestVectors>(
  'private-freshness-request',
);
const [first] = vectors.cases;

describe('PrivateFreshnessRequest', () => {
  it.each(vectors.cases)('reproduces $name', ({ input, requestJson }) => {
    expect(PrivateFreshnessRequest.serialize(input)).toBe(requestJson);
  });

  it.each(vectors.rejected)('rejects $name', ({ input }) => {
    expect(() => PrivateFreshnessRequest.serialize(input)).toThrow(
      new InvalidPrivateFreshnessRequestError(),
    );
  });

  it.each([
    ['a caller-supplied version', { version: 1 }],
    ['a missing nonce', { nonce: undefined }],
  ])('rejects %s', (_name, overrides) => {
    expect(() =>
      PrivateFreshnessRequest.serialize({
        ...first.input,
        ...overrides,
      } as PrivateFreshnessRequestInput),
    ).toThrow(new InvalidPrivateFreshnessRequestError());
  });
});
