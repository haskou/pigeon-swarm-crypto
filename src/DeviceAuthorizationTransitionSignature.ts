import type { DeviceAuthorizationOperation } from './DeviceAuthorizationOperation';
import type { DeviceAuthorizationTransitionPreimage } from './DeviceAuthorizationTransitionPreimage';
import type { DeviceCompromisedCredential } from './DeviceCompromisedCredential';

import { CanonicalJson } from './CanonicalJson';
import { DeviceCredentialCommitment } from './DeviceCredentialCommitment';
import { InvalidDeviceAuthorizationTransitionError } from './errors/InvalidDeviceAuthorizationTransitionError';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

export class DeviceAuthorizationTransitionSignature {
  private static readonly SIGNATURE_DOMAIN =
    'pigeon:device-authorization:transition:v3';

  private static readonly PROOF_DOMAIN =
    'pigeon:device-authorization:proof-of-possession:v2';

  private static readonly OPERATIONS = ['enroll', 'revoke', 'recover'];
  private static readonly PAIRING_FIELDS = [
    'authorizedAt',
    'pairingExpiration',
    'pairingId',
  ] as const;

  public static readonly MAX_COMPROMISED_CREDENTIALS = 32;

  private static compromisedCredentials(
    value: unknown,
    previousRevision: number,
  ): DeviceCompromisedCredential[] {
    const entries = PreimageFields.list(
      value,
      (entry) => {
        const record = PreimageFields.record(entry, [
          'compromisedSince',
          'credential',
        ]);
        const compromisedSince = PreimageFields.counter(
          record.compromisedSince,
        );
        PreimageFields.check(compromisedSince <= previousRevision);

        return {
          compromisedSince,
          credential: PreimageFields.credential(record.credential),
        };
      },
      1,
    );
    PreimageFields.check(
      entries.length <= this.MAX_COMPROMISED_CREDENTIALS &&
        entries.every(
          (entry, index) =>
            index === 0 || entries[index - 1].credential < entry.credential,
        ),
    );

    return entries;
  }

  /** Each operation carries exactly its own optional fields. */
  private static operationFieldsMatch(
    record: Record<string, unknown>,
    operation: DeviceAuthorizationOperation,
  ): boolean {
    const pairing = this.PAIRING_FIELDS.filter(
      (field) => record[field] !== undefined,
    );

    return (
      this.OPERATIONS.includes(operation) &&
      (record.authorCredential === undefined) === (operation === 'recover') &&
      pairing.length ===
        (operation === 'enroll' ? this.PAIRING_FIELDS.length : 0) &&
      (record.compromisedSince === undefined || operation === 'revoke') &&
      (record.compromisedCredentials === undefined || operation === 'recover')
    );
  }

  private static preimage(
    transition: DeviceAuthorizationTransitionPreimage,
  ): DeviceAuthorizationTransitionPreimage {
    const record = PreimageFields.record(
      transition,
      [
        'epoch',
        'identityId',
        'operation',
        'operationId',
        'previousRevision',
        'revision',
        'targetCredential',
        'targetCredentialCommitment',
      ],
      [
        'authorCredential',
        'compromisedCredentials',
        'compromisedSince',
        ...this.PAIRING_FIELDS,
      ],
    );
    const operation = PreimageFields.text(
      record.operation,
    ) as DeviceAuthorizationOperation;
    const previousRevision = PreimageFields.counter(record.previousRevision);
    const targetCredential = PreimageFields.credential(record.targetCredential);
    PreimageFields.check(
      this.operationFieldsMatch(record, operation) &&
        PreimageFields.counter(record.revision) === previousRevision + 1 &&
        record.targetCredentialCommitment ===
          DeviceCredentialCommitment.of(new PublicKey(targetCredential)),
    );
    const compromisedSince = PreimageFields.optional(
      record.compromisedSince,
      (value) => PreimageFields.counter(value),
    );
    PreimageFields.check(
      compromisedSince === undefined || compromisedSince <= previousRevision,
    );

    return {
      authorCredential: PreimageFields.optional(
        record.authorCredential,
        (value) => PreimageFields.credential(value),
      ),
      authorizedAt: PreimageFields.optional(record.authorizedAt, (value) =>
        PreimageFields.counter(value),
      ),
      compromisedCredentials: PreimageFields.optional(
        record.compromisedCredentials,
        (value) => this.compromisedCredentials(value, previousRevision),
      ),
      compromisedSince,
      epoch: PreimageFields.text(record.epoch),
      identityId: PreimageFields.bodyCredential(record.identityId),
      operation,
      operationId: PreimageFields.text(record.operationId),
      pairingExpiration: PreimageFields.optional(
        record.pairingExpiration,
        (value) => PreimageFields.counter(value),
      ),
      pairingId: PreimageFields.optional(record.pairingId, (value) =>
        PreimageFields.text(value),
      ),
      previousRevision,
      revision: previousRevision + 1,
      targetCredential,
      targetCredentialCommitment: record.targetCredentialCommitment as string,
    };
  }

  private static signingText(
    transition: DeviceAuthorizationTransitionPreimage,
    proofOfPossession: Signature | undefined,
  ): string {
    const preimage = this.preimage(transition);
    PreimageFields.check(
      (proofOfPossession === undefined) === (preimage.operation === 'revoke'),
    );

    return CanonicalJson.serialize({
      domain: this.SIGNATURE_DOMAIN,
      proofOfPossession: proofOfPossession?.valueOf(),
      transition: preimage,
    });
  }

  private static proofText(
    transition: DeviceAuthorizationTransitionPreimage,
  ): string {
    const preimage = this.preimage(transition);
    PreimageFields.check(preimage.operation !== 'revoke');

    return CanonicalJson.serialize({
      domain: this.PROOF_DOMAIN,
      transition: preimage,
    });
  }

  public static proofOfPossessionContent(
    transition: DeviceAuthorizationTransitionPreimage,
  ): string {
    return PreimageFields.guarded(
      InvalidDeviceAuthorizationTransitionError,
      () => this.proofText(transition),
    );
  }

  public static signingContent(
    transition: DeviceAuthorizationTransitionPreimage,
    proofOfPossession?: Signature,
  ): string {
    return PreimageFields.guarded(
      InvalidDeviceAuthorizationTransitionError,
      () => this.signingText(transition, proofOfPossession),
    );
  }

  /** Signs the proof of possession with the target device key. */
  public static provePossession(
    transition: DeviceAuthorizationTransitionPreimage,
    targetKey: PrivateKey,
  ): Signature {
    return PreimageFields.guarded(
      InvalidDeviceAuthorizationTransitionError,
      () =>
        PreimageFields.signFor(
          this.proofText(transition),
          targetKey,
          PreimageFields.credentialBody(
            new PublicKey(transition.targetCredential),
          ),
        ),
    );
  }

  /**
   * Signs the transition with the author device key, or with the recovery
   * authority key for a recovery.
   */
  public static sign(
    transition: DeviceAuthorizationTransitionPreimage,
    proofOfPossession: Signature | undefined,
    key: PrivateKey,
  ): Signature {
    return PreimageFields.guarded(
      InvalidDeviceAuthorizationTransitionError,
      () => {
        const content = this.signingText(transition, proofOfPossession);

        return transition.operation === 'recover'
          ? key.sign(content)
          : PreimageFields.signFor(
              content,
              key,
              PreimageFields.credentialBody(
                new PublicKey(transition.authorCredential!),
              ),
            );
      },
    );
  }

  /**
   * Verifies the proof of possession against the target credential and the
   * signature against `key`: the author credential named by the transition,
   * or the recovery authority the caller trusts for a recovery.
   */
  public static verify(
    transition: DeviceAuthorizationTransitionPreimage,
    proofOfPossession: Signature | undefined,
    signature: Signature,
    key: PublicKey,
  ): void {
    PreimageFields.guarded(InvalidDeviceAuthorizationTransitionError, () => {
      const content = this.signingText(transition, proofOfPossession);

      if (proofOfPossession !== undefined)
        PreimageFields.verify(
          this.proofText(transition),
          proofOfPossession,
          new PublicKey(transition.targetCredential),
        );

      if (transition.operation === 'recover')
        PreimageFields.verify(content, signature, key);
      else
        PreimageFields.verifyFor(
          content,
          signature,
          key,
          PreimageFields.credentialBody(
            new PublicKey(transition.authorCredential!),
          ),
        );
    });
  }
}
