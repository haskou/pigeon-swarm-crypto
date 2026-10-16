import { createHash } from 'node:crypto';

import { DeviceCredentialCommitment } from '../../src';
import { loadVectors, publicKeyOf, VectorKey } from '../vectors';

const { keys } = loadVectors<{ keys: Record<string, VectorKey> }>(
  'device-authorization-transition',
);

describe('DeviceCredentialCommitment', () => {
  it.each(Object.entries(keys))('commits to the %s PEM', (_role, key) => {
    expect(DeviceCredentialCommitment.of(publicKeyOf(key))).toBe(
      createHash('sha256').update(key.publicKeyPem, 'utf8').digest('hex'),
    );
  });

  it('separates distinct credentials', () => {
    const [first, second] = Object.values(keys).map((key) =>
      DeviceCredentialCommitment.of(publicKeyOf(key)),
    );

    expect(first).toMatch(/^[0-9a-f]{64}$/);
    expect(first).not.toBe(second);
  });
});
