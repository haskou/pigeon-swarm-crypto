import { DeliveryBase64Url } from './internal/DeliveryBase64Url';
import { InvalidPrivateDeliveryError } from './InvalidPrivateDeliveryError';
import { PrivateDeliveryDescriptorData } from './PrivateDeliveryDescriptorData';

const decodeBase64Url = (value: string, length: number): Uint8Array => {
  return DeliveryBase64Url.decode(value, length);
};

const validateIdentity = (data: PrivateDeliveryDescriptorData): void => {
  const fields = [
    'authorizationRevision',
    'mailboxId',
    'maxCiphertextExpiresAt',
    'recipientPublicKey',
    'validFrom',
    'version',
    'writeValidUntil',
  ];

  if (
    !data ||
    Object.keys(data).sort().join(',') !== fields.sort().join(',') ||
    data.version !== 1 ||
    !Number.isSafeInteger(data.authorizationRevision) ||
    data.authorizationRevision < 0
  ) {
    throw new InvalidPrivateDeliveryError();
  }
  decodeBase64Url(data.mailboxId, 32).fill(0);
  decodeBase64Url(data.recipientPublicKey, 32).fill(0);
};

const validateTimes = (data: PrivateDeliveryDescriptorData): void => {
  if (
    !Number.isSafeInteger(data.validFrom) ||
    data.validFrom < 0 ||
    !Number.isSafeInteger(data.writeValidUntil) ||
    data.writeValidUntil <= data.validFrom
  ) {
    throw new InvalidPrivateDeliveryError();
  }

  if (
    !Number.isSafeInteger(data.maxCiphertextExpiresAt) ||
    data.maxCiphertextExpiresAt < data.writeValidUntil
  ) {
    throw new InvalidPrivateDeliveryError();
  }
};

export class PrivateDeliveryDescriptor {
  public static from(
    data: PrivateDeliveryDescriptorData,
  ): PrivateDeliveryDescriptor {
    try {
      validateIdentity(data);
      validateTimes(data);

      return new PrivateDeliveryDescriptor({ ...data });
    } catch {
      throw new InvalidPrivateDeliveryError();
    }
  }

  private constructor(private readonly data: PrivateDeliveryDescriptorData) {}

  public get authorizationRevision(): number {
    return this.data.authorizationRevision;
  }

  public get mailboxId(): string {
    return this.data.mailboxId;
  }

  public get maxCiphertextExpiresAt(): number {
    return this.data.maxCiphertextExpiresAt;
  }

  public get recipientPublicKey(): string {
    return this.data.recipientPublicKey;
  }

  public get validFrom(): number {
    return this.data.validFrom;
  }

  public get version(): 1 {
    return 1;
  }

  public get writeValidUntil(): number {
    return this.data.writeValidUntil;
  }

  public toJSON(): PrivateDeliveryDescriptorData {
    return { ...this.data };
  }

  public acceptsWrite(now: number, expiresAt: number): boolean {
    return (
      Number.isSafeInteger(now) &&
      now >= this.validFrom &&
      now < this.writeValidUntil &&
      Number.isSafeInteger(expiresAt) &&
      expiresAt >= now &&
      expiresAt <= this.maxCiphertextExpiresAt
    );
  }
}
