import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidPrivateGenesisError } from '../errors/InvalidPrivateGenesisError';
import { CanonicalBase64Url } from './CanonicalBase64Url';
import { StrictCanonicalJson } from './StrictCanonicalJson';

export class PrivateGenesisEncoding {
  private static readonly headFields = [
    'scopeId',
    'revision',
    'parentHeadHash',
    'mlsEpoch',
    'mlsContextHash',
    'policyHash',
  ];

  private static record(value: unknown): Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new InvalidPrivateGenesisError();

    return value as Record<string, unknown>;
  }

  private static fields(
    value: Record<string, unknown>,
    fields: string[],
  ): void {
    if (
      Object.keys(value).length !== fields.length ||
      fields.some((field) => !Object.hasOwn(value, field))
    )
      throw new InvalidPrivateGenesisError();
  }

  private static singleton(value: unknown): unknown {
    if (!Array.isArray(value) || value.length !== 1)
      throw new InvalidPrivateGenesisError();

    return value[0];
  }

  private static hash(value: Record<string, unknown>): string {
    return CanonicalBase64Url.encode(
      sha256(Buffer.from(StrictCanonicalJson.serialize(value), 'utf8')),
    );
  }

  private static policy(
    value: unknown,
    owner: string,
  ): Record<string, unknown> {
    const policy = this.record(value);
    this.fields(policy, [
      'version',
      'devices',
      'authorityKeys',
      'threshold',
      'sequencerKey',
      'freshnessAuthorityKey',
      'leaseRevocationKey',
      'leaseRevocationHpkeKey',
    ]);
    const device = this.record(this.singleton(policy.devices));
    this.fields(device, ['deviceKey', 'mlsCredentialHash']);
    CanonicalBase64Url.decode(device.mlsCredentialHash, 32);
    CanonicalBase64Url.decode(policy.leaseRevocationHpkeKey, 32);

    if (
      policy.version !== 1 ||
      policy.threshold !== 1 ||
      this.singleton(policy.authorityKeys) !== owner ||
      device.deviceKey !== owner ||
      ['sequencerKey', 'freshnessAuthorityKey', 'leaseRevocationKey'].some(
        (role) => policy[role] !== owner,
      ) ||
      policy.leaseRevocationHpkeKey === owner
    )
      throw new InvalidPrivateGenesisError();

    return policy;
  }

  private static checkHashes(
    value: Record<string, unknown>,
    policy: Record<string, unknown>,
  ): void {
    const head = Object.fromEntries(
      this.headFields.map((field) => [field, value[field]]),
    );

    if (
      value.policyHash !== this.hash(policy) ||
      value.headHash !== this.hash(head)
    )
      throw new InvalidPrivateGenesisError();
  }

  public static validate(
    value: Record<string, unknown>,
    owner: string,
    signed: boolean,
  ): void {
    const fields = ['version', ...this.headFields, 'headHash', 'policy'];
    this.fields(value, signed ? [...fields, 'signatures'] : fields);
    CanonicalBase64Url.decode(owner, 32);
    CanonicalBase64Url.decode(value.scopeId, 32);
    CanonicalBase64Url.decode(value.mlsContextHash, 32);

    if (
      value.version !== 1 ||
      value.revision !== 0 ||
      value.mlsEpoch !== 0 ||
      value.parentHeadHash !== null
    )
      throw new InvalidPrivateGenesisError();
    const policy = this.policy(value.policy, owner);
    this.checkHashes(value, policy);

    if (signed) {
      const signatures = this.record(value.signatures);
      this.fields(signatures, [owner]);
      CanonicalBase64Url.decode(signatures[owner], 64);
    }
  }
}
