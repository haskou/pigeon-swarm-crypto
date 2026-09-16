import { inspect } from 'node:util';

import { PrivateKey, PublicKey, SymmetricKey } from '../../src';

const marker = 'PRIVATE-MATERIAL-DO-NOT-LOG';

describe('Secret validation errors', () => {
  it.each([
    ['private key length', () => new PrivateKey(marker)],
    ['private key format', () => new PrivateKey(marker.padEnd(119, '!'))],
    ['public key length', () => new PublicKey(marker)],
    ['public key format', () => new PublicKey(marker.padEnd(113, '!'))],
    ['symmetric key format', () => new SymmetricKey(marker)],
  ])('does not expose submitted material in %s errors', (_, operation) => {
    let failure: unknown;
    try {
      operation();
    } catch (error) {
      failure = error;
    }

    expect(failure).toBeInstanceOf(Error);
    for (const rendered of [
      String(failure),
      JSON.stringify(failure),
      inspect(failure, { showHidden: true, depth: null }),
    ])
      expect(rendered).not.toContain(marker);
  });
});
