import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';

const sourceRoot = join(__dirname, '..', '..', 'src');
const adapter = join('internal', 'CryptoAdapter.ts');
const verifyCall = /\bed25519\s*\.\s*verify\b/g;

const verifyCallsIn = (file: string): number =>
  [...readFileSync(join(sourceRoot, file), 'utf8').matchAll(verifyCall)].length;

const sourceFiles = (): string[] =>
  readdirSync(sourceRoot, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.ts'))
    .map((entry) => relative(sourceRoot, join(entry.parentPath, entry.name)));

describe('Ed25519 verify path', () => {
  it('verifies every Ed25519 signature through CryptoAdapter.verify', () => {
    const callers = sourceFiles().filter(
      (file) => file !== adapter && verifyCallsIn(file) > 0,
    );

    expect(callers).toEqual([]);
    expect(verifyCallsIn(adapter)).toBe(1);
  });
});
