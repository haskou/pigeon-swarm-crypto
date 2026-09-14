import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';

import { InvalidPrivateControlError } from '../errors/InvalidPrivateControlError';
import { CanonicalBase64Url } from './CanonicalBase64Url';
import { PrivateAuthorizationPolicyEncoding } from './PrivateAuthorizationPolicyEncoding';
import { PrivateControlRecord } from './PrivateControlRecord';
import { StrictCanonicalJson } from './StrictCanonicalJson';

export class PrivateControlEncoding {
  private static readonly headFields = [
    'scopeId',
    'revision',
    'parentHeadHash',
    'mlsEpoch',
    'mlsContextHash',
    'policyHash',
  ];

  private static counter(value: unknown): void {
    if (!Number.isSafeInteger(value) || (value as number) < 0)
      throw new InvalidPrivateControlError();
  }

  private static hash(value: Record<string, unknown>): string {
    return CanonicalBase64Url.encode(
      sha256(Buffer.from(StrictCanonicalJson.serialize(value), 'utf8')),
    );
  }

  private static previous(value: unknown): Record<string, unknown> {
    const previous = PrivateControlRecord.read(value, [
      'scopeId',
      'revision',
      'headHash',
      'mlsEpoch',
      'policy',
    ]);
    CanonicalBase64Url.decode(previous.scopeId, 32);
    CanonicalBase64Url.decode(previous.headHash, 32);
    this.counter(previous.revision);
    this.counter(previous.mlsEpoch);
    PrivateAuthorizationPolicyEncoding.validate(previous.policy);

    return previous;
  }

  private static checkParent(
    value: Record<string, unknown>,
    previous: Record<string, unknown>,
  ): void {
    this.counter(value.revision);
    this.counter(value.mlsEpoch);

    if (
      value.scopeId !== previous.scopeId ||
      value.parentHeadHash !== previous.headHash ||
      value.revision !== (previous.revision as number) + 1 ||
      value.mlsEpoch !== (previous.mlsEpoch as number) + 1
    )
      throw new InvalidPrivateControlError();
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
      throw new InvalidPrivateControlError();
  }

  public static validate(
    value: Record<string, unknown>,
    trustedCheckpoint: Record<string, unknown>,
    expectedMlsMessageHash: string,
  ): Record<string, unknown> {
    PrivateControlRecord.read(value, [
      ...this.headFields,
      'headHash',
      'mlsMessageHash',
      'policy',
      'signatures',
    ]);
    const previous = this.previous(trustedCheckpoint);
    this.checkParent(value, previous);
    CanonicalBase64Url.decode(value.mlsMessageHash, 32);
    CanonicalBase64Url.decode(value.mlsContextHash, 32);

    if (value.mlsMessageHash !== expectedMlsMessageHash)
      throw new InvalidPrivateControlError();
    const policy = PrivateAuthorizationPolicyEncoding.validate(value.policy);
    this.checkHashes(value, policy);
    const previousPolicy = previous.policy as Record<string, unknown>;

    if (
      policy.leaseRevocationKey !== previousPolicy.leaseRevocationKey ||
      policy.leaseRevocationHpkeKey !== previousPolicy.leaseRevocationHpkeKey
    )
      throw new InvalidPrivateControlError();

    return previousPolicy;
  }
}
