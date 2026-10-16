import {
  DeviceUnlockFactor,
  InvalidDeviceUnlockFactorError,
  UserRootKeySecondFactor,
} from '../../src';
import vectors from '../../vectors/device-unlock-factor.json';

const importKey = (
  raw: string,
  algorithm: HmacImportParams = { hash: 'SHA-256', length: 256, name: 'HMAC' },
  usages: KeyUsage[] = ['sign'],
): Promise<CryptoKey> =>
  crypto.subtle.importKey(
    'raw',
    Buffer.from(raw, 'base64url'),
    algorithm,
    false,
    usages,
  );

describe('DeviceUnlockFactor', () => {
  const [first] = vectors.cases;

  it.each(vectors.cases)(
    'derives the second factor of $deviceId',
    async ({ context, deviceId, factorKey, identityId, secondFactor, secretHandle }) => {
      expect(DeviceUnlockFactor.context(identityId, deviceId, secretHandle)).toBe(
        context,
      );

      const factor = await DeviceUnlockFactor.derive(
        await importKey(factorKey),
        identityId,
        deviceId,
        secretHandle,
      );

      expect(
        factor.isEqual(UserRootKeySecondFactor.fromBase64(secondFactor)),
      ).toBeTrue();
    },
  );

  it.each([
    ['an empty identity', '', first.deviceId, first.secretHandle],
    ['a multi-line device', first.identityId, 'a\nb', first.secretHandle],
    ['an oversized handle', first.identityId, first.deviceId, 'a'.repeat(4097)],
    ['a non-string handle', first.identityId, first.deviceId, 1],
  ])('rejects %s', async (_, identityId, deviceId, secretHandle) => {
    expect(() =>
      DeviceUnlockFactor.context(identityId, deviceId, secretHandle as string),
    ).toThrow(new InvalidDeviceUnlockFactorError());
    await expect(
      DeviceUnlockFactor.derive(
        await importKey(first.factorKey),
        identityId,
        deviceId,
        secretHandle as string,
      ),
    ).rejects.toThrow(InvalidDeviceUnlockFactorError);
  });

  it.each([
    [
      'a SHA-512 key',
      () =>
        importKey(first.factorKey, {
          hash: 'SHA-512',
          length: 256,
          name: 'HMAC',
        }),
    ],
    [
      'a short key',
      () =>
        importKey(Buffer.alloc(16).toString('base64url'), {
          hash: 'SHA-256',
          name: 'HMAC',
        }),
    ],
    ['a verify-only key', () => importKey(first.factorKey, undefined, ['verify'])],
    [
      'an AES key',
      () =>
        crypto.subtle.importKey('raw', Buffer.alloc(32), 'AES-GCM', false, [
          'encrypt',
        ]),
    ],
    ['a raw key', () => Promise.resolve(Buffer.alloc(32))],
    ['no key', () => Promise.resolve(undefined)],
  ])('rejects %s', async (_, factorKey) => {
    await expect(
      DeviceUnlockFactor.derive(
        (await factorKey()) as CryptoKey,
        first.identityId,
        first.deviceId,
        first.secretHandle,
      ),
    ).rejects.toThrow(InvalidDeviceUnlockFactorError);
  });
});
