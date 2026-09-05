import { DomainError } from '@haskou/value-objects';

import {
  InvalidEncryptedPrivateKeyFormatError,
  InvalidKeyError,
  InvalidSignatureError,
} from '../../src';

describe('crypto errors', () => {
  it('exposes domain-specific errors', () => {
    const format = new InvalidEncryptedPrivateKeyFormatError();
    const customFormat = new InvalidEncryptedPrivateKeyFormatError('reason');
    const key = new InvalidKeyError(128, [256, 512]);
    const signature = new InvalidSignatureError(88);

    expect(format).toBeInstanceOf(DomainError);
    expect(format.message).toContain('Invalid encrypted private key format');
    expect(customFormat.message).toContain('reason');
    expect(key).toBeInstanceOf(DomainError);
    expect(key.message).toContain('128');
    expect(signature).toBeInstanceOf(DomainError);
    expect(signature.message).toContain('88');
  });
});
