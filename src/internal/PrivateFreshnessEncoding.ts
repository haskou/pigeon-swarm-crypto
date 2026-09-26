import { InvalidPrivateFreshnessProofError } from '../errors/InvalidPrivateFreshnessProofError';
import { CanonicalBase64Url } from './CanonicalBase64Url';

export class PrivateFreshnessEncoding {
  private static readonly REQUEST_FIELDS = [
    'version',
    'scopeId',
    'nonce',
    'expectedRevision',
    'expectedHeadHash',
    'batchCommitment',
  ];

  private static readonly PROOF_FIELDS = [
    'version',
    'scopeId',
    'nonce',
    'revision',
    'headHash',
    'batchCommitment',
    'signerKey',
  ];

  private static hasExactFields(
    value: Record<string, unknown>,
    fields: string[],
  ): boolean {
    const names = Object.keys(value).sort();
    const expected = [...fields].sort();

    return (
      names.length === expected.length &&
      names.every((name, index) => name === expected[index])
    );
  }

  private static validateEncoded32(value: unknown): void {
    if (typeof value !== 'string')
      throw new InvalidPrivateFreshnessProofError();
    CanonicalBase64Url.decode(value, 32);
  }

  private static validateRevision(value: unknown): void {
    if (!Number.isSafeInteger(value) || (value as number) < 0)
      throw new InvalidPrivateFreshnessProofError();
  }

  public static validateRequest(value: Record<string, unknown>): void {
    if (!this.hasExactFields(value, this.REQUEST_FIELDS) || value.version !== 1)
      throw new InvalidPrivateFreshnessProofError();
    this.validateEncoded32(value.scopeId);
    this.validateEncoded32(value.nonce);
    this.validateRevision(value.expectedRevision);
    this.validateEncoded32(value.expectedHeadHash);
    this.validateEncoded32(value.batchCommitment);
  }

  public static validateProof(
    value: Record<string, unknown>,
    signatureRequired: boolean,
  ): void {
    const fields = signatureRequired
      ? [...this.PROOF_FIELDS, 'signature']
      : this.PROOF_FIELDS;

    if (!this.hasExactFields(value, fields) || value.version !== 1)
      throw new InvalidPrivateFreshnessProofError();
    this.validateEncoded32(value.scopeId);
    this.validateEncoded32(value.nonce);
    this.validateRevision(value.revision);
    this.validateEncoded32(value.headHash);
    this.validateEncoded32(value.batchCommitment);
    this.validateEncoded32(value.signerKey);

    if (signatureRequired) {
      if (typeof value.signature !== 'string')
        throw new InvalidPrivateFreshnessProofError();
      CanonicalBase64Url.decode(value.signature, 64);
    }
  }
}
