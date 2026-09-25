import { Buffer } from 'buffer';
import canonicalize from 'canonicalize';

import { DeliveryBase64Url } from './internal/DeliveryBase64Url';
import { getMlsCiphersuite } from './internal/MlsRuntime';
import {
  MAX_PRIVATE_DELIVERY_RETENTION_MS,
  PRIVATE_DELIVERY_DAY_MS,
} from './internal/PrivateDeliveryPolicy';
import { InvalidPrivateDeliveryError } from './InvalidPrivateDeliveryError';
import { MlsCredential } from './MlsCredential';
import { PrivateDeliveryDescriptor } from './PrivateDeliveryDescriptor';
import { PrivateDeliveryScheduleDocument } from './PrivateDeliveryScheduleDocument';

const DOMAIN = 'pigeon.private-delivery-schedule.v1\0';
const MAX_BYTES = 32768;

const encodeIdentity = (value: Uint8Array): string =>
  DeliveryBase64Url.encode(value);

const decodeIdentity = (value: unknown, maximumLength: number): Uint8Array => {
  if (typeof value !== 'string') throw new InvalidPrivateDeliveryError();
  const bytes = DeliveryBase64Url.decodeAtMost(value, maximumLength);

  return bytes;
};

const unsignedBytes = (
  value: Omit<PrivateDeliveryScheduleDocument, 'signature'>,
): Uint8Array => Buffer.from(DOMAIN + canonicalize(value)!, 'utf8');

const validateSerialized = (signedJson: string): void => {
  if (typeof signedJson !== 'string') throw new InvalidPrivateDeliveryError();

  if (Buffer.byteLength(signedJson) > MAX_BYTES) {
    throw new InvalidPrivateDeliveryError();
  }
};

const parse = (signedJson: string): PrivateDeliveryScheduleDocument => {
  validateSerialized(signedJson);
  const value = JSON.parse(signedJson) as PrivateDeliveryScheduleDocument;
  const fields = [
    'descriptors',
    'signature',
    'signerIdentity',
    'signerPublicKey',
    'version',
  ];

  if (
    !value ||
    Object.keys(value).sort().join(',') !== fields.sort().join(',') ||
    value.version !== 1 ||
    !Array.isArray(value.descriptors)
  ) {
    throw new InvalidPrivateDeliveryError();
  }

  if (value.descriptors.length === 0 || value.descriptors.length > 8) {
    throw new InvalidPrivateDeliveryError();
  }

  if (canonicalize(value) !== signedJson)
    throw new InvalidPrivateDeliveryError();

  return value;
};

const validateDescriptorSequence = (
  descriptors: readonly PrivateDeliveryDescriptor[],
): void => {
  const mailboxIds = new Set(descriptors.map((value) => value.mailboxId));
  const publicKeys = new Set(
    descriptors.map((value) => value.recipientPublicKey),
  );

  if (
    mailboxIds.size !== descriptors.length ||
    publicKeys.size !== descriptors.length
  ) {
    throw new InvalidPrivateDeliveryError();
  }
  const retention =
    descriptors[0].maxCiphertextExpiresAt - descriptors[0].writeValidUntil;

  if (retention > MAX_PRIVATE_DELIVERY_RETENTION_MS) {
    throw new InvalidPrivateDeliveryError();
  }
  descriptors.forEach((descriptor, index) => {
    if (
      descriptor.writeValidUntil - descriptor.validFrom !==
      PRIVATE_DELIVERY_DAY_MS
    ) {
      throw new InvalidPrivateDeliveryError();
    }

    if (
      descriptor.maxCiphertextExpiresAt - descriptor.writeValidUntil !==
      retention
    ) {
      throw new InvalidPrivateDeliveryError();
    }

    if (
      index > 0 &&
      descriptor.validFrom !== descriptors[index - 1].writeValidUntil
    ) {
      throw new InvalidPrivateDeliveryError();
    }
  });
};

const validateRecipientKeys = async (
  descriptors: readonly PrivateDeliveryDescriptor[],
): Promise<void> => {
  const suite = await getMlsCiphersuite();
  for (const descriptor of descriptors) {
    const publicKey = DeliveryBase64Url.decode(
      descriptor.recipientPublicKey,
      32,
    );

    try {
      await suite.hpke.importPublicKey(publicKey);
    } finally {
      publicKey.fill(0);
    }
  }
};

export class AuthenticatedPrivateDeliverySchedule {
  private readonly scheduleDescriptors: readonly PrivateDeliveryDescriptor[];

  public static async sign(
    descriptors: readonly PrivateDeliveryDescriptor[],
    credential: MlsCredential,
    signaturePrivateKey: Uint8Array,
  ): Promise<AuthenticatedPrivateDeliverySchedule> {
    try {
      if (descriptors.length === 0 || descriptors.length > 8) {
        throw new InvalidPrivateDeliveryError();
      }
      validateDescriptorSequence(descriptors);
      await validateRecipientKeys(descriptors);
      const unsigned: Omit<PrivateDeliveryScheduleDocument, 'signature'> = {
        descriptors: descriptors.map((descriptor) => descriptor.toJSON()),
        signerIdentity: encodeIdentity(credential.identity),
        signerPublicKey: encodeIdentity(credential.signaturePublicKey),
        version: 1,
      };
      const suite = await getMlsCiphersuite();
      const signature = await suite.signature.sign(
        signaturePrivateKey,
        unsignedBytes(unsigned),
      );
      const signed = canonicalize({
        ...unsigned,
        signature: DeliveryBase64Url.encode(signature),
      })!;
      signature.fill(0);

      return new AuthenticatedPrivateDeliverySchedule(signed, descriptors);
    } catch {
      throw new InvalidPrivateDeliveryError();
    }
  }

  public static async verify(
    signedJson: string,
    expectedCredential: MlsCredential,
    expectedAuthorizationRevision: number,
  ): Promise<AuthenticatedPrivateDeliverySchedule> {
    try {
      const signed = parse(signedJson);
      const { signature, ...unsigned } = signed;

      if (
        unsigned.signerIdentity !==
          encodeIdentity(expectedCredential.identity) ||
        unsigned.signerPublicKey !==
          encodeIdentity(expectedCredential.signaturePublicKey)
      ) {
        throw new InvalidPrivateDeliveryError();
      }
      const signatureBytes = decodeIdentity(signature, 64);

      if (signatureBytes.length !== 64) throw new InvalidPrivateDeliveryError();
      const descriptors = unsigned.descriptors.map((value) =>
        PrivateDeliveryDescriptor.from(value),
      );
      validateDescriptorSequence(descriptors);
      await validateRecipientKeys(descriptors);

      if (
        descriptors.some(
          (descriptor) =>
            descriptor.authorizationRevision !== expectedAuthorizationRevision,
        )
      ) {
        throw new InvalidPrivateDeliveryError();
      }
      const suite = await getMlsCiphersuite();
      const valid = await suite.signature.verify(
        expectedCredential.signaturePublicKey,
        unsignedBytes(unsigned),
        signatureBytes,
      );

      if (!valid) throw new InvalidPrivateDeliveryError();

      return new AuthenticatedPrivateDeliverySchedule(signedJson, descriptors);
    } catch {
      throw new InvalidPrivateDeliveryError();
    }
  }

  private constructor(
    private readonly signedJson: string,
    descriptors: readonly PrivateDeliveryDescriptor[],
  ) {
    this.scheduleDescriptors = Object.freeze([...descriptors]);
  }

  public get descriptors(): readonly PrivateDeliveryDescriptor[] {
    return this.scheduleDescriptors;
  }

  public valueOf(): string {
    return this.signedJson;
  }
}
