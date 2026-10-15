import { Buffer } from 'buffer';

import { InvalidDeviceUnlockFactorError } from './errors/InvalidDeviceUnlockFactorError';
import { BoundedText } from './internal/BoundedText';
import { UserRootKeySecondFactor } from './UserRootKeySecondFactor';

export class DeviceUnlockFactor {
  private static readonly DOMAIN = 'pigeon-swarm:device-unlock-factor:v1';
  private static readonly KEY_BITS = 256;
  private static readonly MAX_COMPONENT_BYTES = 4096;

  private static component(value: string): string {
    BoundedText.encode(value, DeviceUnlockFactor.MAX_COMPONENT_BYTES);

    if (value.includes('\n')) throw new InvalidDeviceUnlockFactorError();

    return value;
  }

  private static isFactorKey(factorKey: CryptoKey): boolean {
    const algorithm = factorKey?.algorithm as HmacKeyAlgorithm | undefined;

    return (
      algorithm?.name === 'HMAC' &&
      algorithm.hash?.name === 'SHA-256' &&
      algorithm.length === DeviceUnlockFactor.KEY_BITS &&
      factorKey.usages.includes('sign')
    );
  }

  public static context(
    identityId: string,
    deviceId: string,
    secretHandle: string,
  ): string {
    try {
      return [
        DeviceUnlockFactor.DOMAIN,
        this.component(identityId),
        this.component(deviceId),
        this.component(secretHandle),
      ].join('\n');
    } catch {
      throw new InvalidDeviceUnlockFactorError();
    }
  }

  public static async derive(
    factorKey: CryptoKey,
    identityId: string,
    deviceId: string,
    secretHandle: string,
  ): Promise<UserRootKeySecondFactor> {
    try {
      if (!this.isFactorKey(factorKey))
        throw new InvalidDeviceUnlockFactorError();
      const mac = new Uint8Array(
        await globalThis.crypto.subtle.sign(
          'HMAC',
          factorKey,
          Buffer.from(this.context(identityId, deviceId, secretHandle), 'utf8'),
        ),
      );

      try {
        return UserRootKeySecondFactor.fromBuffer(mac);
      } finally {
        mac.fill(0);
      }
    } catch {
      throw new InvalidDeviceUnlockFactorError();
    }
  }
}
