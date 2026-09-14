import { InvalidPrivateControlError } from '../errors/InvalidPrivateControlError';
import { CanonicalBase64Url } from './CanonicalBase64Url';
import { PrivateControlRecord } from './PrivateControlRecord';

export class PrivateAuthorizationPolicyEncoding {
  private static list(value: unknown): unknown[] {
    if (!Array.isArray(value) || value.length < 1 || value.length > 128)
      throw new InvalidPrivateControlError();

    return value;
  }

  private static deviceKeys(value: unknown): unknown[] {
    const devices = this.list(value).map((item) =>
      PrivateControlRecord.read(item, ['deviceKey', 'mlsCredentialHash']),
    );
    for (const device of devices) {
      CanonicalBase64Url.decode(device.deviceKey, 32);
      CanonicalBase64Url.decode(device.mlsCredentialHash, 32);
    }
    const keys = devices.map((device) => device.deviceKey);
    const credentials = devices.map((device) => device.mlsCredentialHash);

    if (
      new Set(keys).size !== keys.length ||
      new Set(credentials).size !== credentials.length
    )
      throw new InvalidPrivateControlError();

    return keys;
  }

  private static authorityKeys(value: unknown, devices: unknown[]): unknown[] {
    const authorities = this.list(value);
    for (const authority of authorities)
      CanonicalBase64Url.decode(authority, 32);

    if (
      new Set(authorities).size !== authorities.length ||
      authorities.some((key) => !devices.includes(key))
    )
      throw new InvalidPrivateControlError();

    return authorities;
  }

  private static checkThreshold(value: unknown, count: number): void {
    if (
      !Number.isSafeInteger(value) ||
      (value as number) < 1 ||
      (value as number) > count
    )
      throw new InvalidPrivateControlError();
  }

  public static validate(value: unknown): Record<string, unknown> {
    const policy = PrivateControlRecord.read(value, [
      'version',
      'devices',
      'authorityKeys',
      'threshold',
      'sequencerKey',
      'freshnessAuthorityKey',
      'leaseRevocationKey',
      'leaseRevocationHpkeKey',
    ]);
    const devices = this.deviceKeys(policy.devices);
    const authorities = this.authorityKeys(policy.authorityKeys, devices);
    this.checkThreshold(policy.threshold, authorities.length);
    CanonicalBase64Url.decode(policy.leaseRevocationKey, 32);
    CanonicalBase64Url.decode(policy.leaseRevocationHpkeKey, 32);

    if (
      policy.version !== 1 ||
      !authorities.includes(policy.sequencerKey) ||
      !devices.includes(policy.freshnessAuthorityKey) ||
      policy.leaseRevocationKey === policy.leaseRevocationHpkeKey
    )
      throw new InvalidPrivateControlError();

    return policy;
  }
}
