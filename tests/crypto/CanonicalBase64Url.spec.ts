import { InvalidPrivateOperationError } from '../../src';
import { CanonicalBase64Url } from '../../src/internal/CanonicalBase64Url';

describe('CanonicalBase64Url.decodeBounded', () => {
  it('decodes canonical unpadded base64url up to the bound', () => {
    expect(CanonicalBase64Url.decodeBounded('', 3)).toEqual(Buffer.alloc(0));
    expect(CanonicalBase64Url.decodeBounded('-_-_', 3)).toEqual(
      Buffer.from('-_-_', 'base64url'),
    );
  });

  it.each([
    ['an oversized value', 'AAAAAA', 3],
    ['a padded value', 'AA==', 3],
    ['a standard base64 value', '+/+/', 3],
    ['a non-canonical tail', 'AB', 3],
  ])('rejects %s', (_, value, maxLength) => {
    expect(() => CanonicalBase64Url.decodeBounded(value, maxLength)).toThrow(
      InvalidPrivateOperationError,
    );
  });
});
