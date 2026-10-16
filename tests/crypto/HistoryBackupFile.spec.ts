import {
  HistoryBackupFile,
  InvalidHistoryBackupError,
  SymmetricKey,
} from '../../src';
import { CryptoAdapter } from '../../src/internal/CryptoAdapter';
import vectors from '../../vectors/history-backup.json';

const bytes = (value: string): Buffer => Buffer.from(value, 'base64url');

describe('HistoryBackupFile', () => {
  const root = SymmetricKey.fromBase64(vectors.root);
  const { identityId } = vectors;
  const [, second] = vectors.seal;
  const parsed = JSON.parse(second.file) as Record<string, unknown>;

  afterEach(() => jest.restoreAllMocks());

  it.each(vectors.seal)(
    'seals and opens a $plaintext.length character plaintext',
    ({ file, iv, plaintext }) => {
      jest.spyOn(CryptoAdapter, 'randomBytes').mockReturnValueOnce(bytes(iv));

      expect(HistoryBackupFile.seal(root, identityId, bytes(plaintext))).toBe(
        file,
      );
      expect(
        Buffer.from(HistoryBackupFile.open(root, identityId, file)).toString(
          'base64url',
        ),
      ).toBe(plaintext);
    },
  );

  it('binds the file to its identity and root key', () => {
    expect(() =>
      HistoryBackupFile.open(root, 'other-identity', second.file),
    ).toThrow(new InvalidHistoryBackupError());
    expect(() =>
      HistoryBackupFile.open(SymmetricKey.generate(), identityId, second.file),
    ).toThrow(InvalidHistoryBackupError);
  });

  it.each([
    ['a non-string file', 1],
    ['an oversized file', ' '.repeat(Math.ceil(((128 * 1024 * 1024 + 16) * 4) / 3) + 129)],
    ['invalid JSON', '{'],
    ['a null file', 'null'],
    [
      'a reordered file',
      JSON.stringify({
        iv: parsed.iv,
        ciphertext: parsed.ciphertext,
        format: parsed.format,
        version: parsed.version,
      }),
    ],
    ['another format', JSON.stringify({ ...parsed, format: 'other' })],
    ['another version', JSON.stringify({ ...parsed, version: 2 })],
    ['a non-string ciphertext', JSON.stringify({ ...parsed, ciphertext: 1 })],
    ['a non-string iv', JSON.stringify({ ...parsed, iv: 1 })],
    ['a whitespace-padded file', ` ${second.file}`],
    ['a padded ciphertext', JSON.stringify({ ...parsed, ciphertext: `${String(parsed.ciphertext)}=` })],
    ['a short iv', JSON.stringify({ ...parsed, iv: String(parsed.iv).slice(4) })],
    ['a truncated ciphertext', JSON.stringify({ ...parsed, ciphertext: String(parsed.ciphertext).slice(4) })],
  ])('refuses %s', (_, file) => {
    expect(() =>
      HistoryBackupFile.open(root, identityId, file as string),
    ).toThrow(InvalidHistoryBackupError);
  });

  it.each([
    ['a non-byte plaintext', root, identityId, 'plaintext'],
    [
      'an oversized plaintext',
      root,
      identityId,
      new Uint8Array(HistoryBackupFile.MAX_PLAINTEXT_BYTES + 1),
    ],
    ['an empty identity', root, '', new Uint8Array()],
    ['a raw root key', Buffer.alloc(32), identityId, new Uint8Array()],
  ])('refuses to seal %s', (_, key, id, plaintext) => {
    expect(() =>
      HistoryBackupFile.seal(
        key as SymmetricKey,
        id,
        plaintext as Uint8Array,
      ),
    ).toThrow(InvalidHistoryBackupError);
  });
});
