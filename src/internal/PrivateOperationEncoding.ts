import { InvalidPrivateOperationError } from '../errors/InvalidPrivateOperationError';
import { CanonicalBase64Url } from './CanonicalBase64Url';

export class PrivateOperationEncoding {
  private static readonly fields = [
    'version',
    'operationId',
    'scopeId',
    'authorizationRevision',
    'authorDeviceKey',
    'kind',
    'previousOperationIds',
    'payload',
  ];

  private static readonly kinds = new Set([
    'message.create',
    'message.edit',
    'message.delete',
    'reaction.set',
    'receipt.advance',
    'call.signal',
    'membership.propose',
    'membership.commit',
    'device.revoke',
    'presence.update',
  ]);

  private static checkLinks(value: unknown): void {
    if (
      !Array.isArray(value) ||
      value.length > 32 ||
      new Set(value).size !== value.length
    )
      throw new InvalidPrivateOperationError();
    for (const id of value) CanonicalBase64Url.decode(id, 16);
  }

  private static checkPayload(payload: unknown): void {
    if (!payload || typeof payload !== 'object' || Array.isArray(payload))
      throw new InvalidPrivateOperationError();
  }

  private static checkFields(
    value: Record<string, unknown>,
    signed: boolean,
  ): void {
    const fields = signed ? [...this.fields, 'signature'] : this.fields;

    if (
      Object.keys(value).length !== fields.length ||
      fields.some((field) => !Object.hasOwn(value, field))
    )
      throw new InvalidPrivateOperationError();
  }

  public static validate(
    value: Record<string, unknown>,
    signed: boolean,
  ): void {
    this.checkFields(value, signed);

    if (value.version !== 1 || !this.kinds.has(value.kind as string))
      throw new InvalidPrivateOperationError();

    if (
      !Number.isSafeInteger(value.authorizationRevision) ||
      (value.authorizationRevision as number) < 0
    )
      throw new InvalidPrivateOperationError();

    this.checkPayload(value.payload);
    CanonicalBase64Url.decode(value.operationId, 16);
    CanonicalBase64Url.decode(value.scopeId, 32);
    CanonicalBase64Url.decode(value.authorDeviceKey, 32);
    this.checkLinks(value.previousOperationIds);

    if (signed) CanonicalBase64Url.decode(value.signature, 64);
  }
}
