import { Buffer } from 'buffer';
import canonicalize from 'canonicalize';

import { CryptoAdapter } from '../internal/CryptoAdapter';
import { DeliveryBase64Url } from './internal/DeliveryBase64Url';
import { getMlsCiphersuite } from './internal/MlsRuntime';
import { InvalidPrivateDeliveryError } from './InvalidPrivateDeliveryError';
import { PrivateDeliveryBucketBytes } from './PrivateDeliveryBucketBytes';
import { PrivateDeliveryDescriptor } from './PrivateDeliveryDescriptor';
import { PrivateDeliveryEnvelopeData } from './PrivateDeliveryEnvelopeData';
import { PrivateDeliveryFrame } from './PrivateDeliveryFrame';
import { PrivateDeliveryHeader } from './PrivateDeliveryHeader';

const BUCKETS = new Set<number>([4096, 16384, 65536, 262144]);
const ENCAPSULATED_KEY_BYTES = 32;
const TAG_BYTES = 16;
const INFO = new TextEncoder().encode('pigeon.private-delivery.v1\0');

const randomIdentifier = (length: number): string => {
  const value = CryptoAdapter.randomBytes(length);

  try {
    return DeliveryBase64Url.encode(value);
  } finally {
    value.fill(0);
  }
};

const decodeBase64Url = (value: unknown, length: number): Uint8Array => {
  return DeliveryBase64Url.decode(value, length);
};

const validateOpenInputs = (
  value: PrivateDeliveryEnvelopeData,
  privateKeyBytes: Uint8Array,
  now: number,
): void => {
  if (!Number.isSafeInteger(now) || now < 0 || now > value.expiresAt) {
    throw new InvalidPrivateDeliveryError();
  }

  if (typeof value.ciphertext !== 'string' || privateKeyBytes.length !== 32) {
    throw new InvalidPrivateDeliveryError();
  }
};

const decodeWire = (value: PrivateDeliveryEnvelopeData): Buffer => {
  const wire = Buffer.from(value.ciphertext, 'base64');

  if (wire.length !== value.bucketBytes)
    throw new InvalidPrivateDeliveryError();

  if (wire.toString('base64') !== value.ciphertext) {
    throw new InvalidPrivateDeliveryError();
  }

  return wire;
};

const validateEnvelopeShape = (value: PrivateDeliveryEnvelopeData): void => {
  const fields = [
    'bucketBytes',
    'ciphertext',
    'deliveryId',
    'expiresAt',
    'mailboxId',
    'version',
  ];

  if (Object.keys(value).sort().join(',') !== fields.sort().join(',')) {
    throw new InvalidPrivateDeliveryError();
  }
};

const validateHeaderShape = (value: PrivateDeliveryHeader): void => {
  const fields = [
    'bucketBytes',
    'deliveryId',
    'expiresAt',
    'mailboxId',
    'version',
  ];

  if (Object.keys(value).sort().join(',') !== fields.sort().join(',')) {
    throw new InvalidPrivateDeliveryError();
  }
};

const decodeFrame = (
  plaintext: Uint8Array,
  bucketBytes: number,
): PrivateDeliveryFrame => {
  if (plaintext.length !== bucketBytes - 48) {
    throw new InvalidPrivateDeliveryError();
  }
  const length = new DataView(
    plaintext.buffer,
    plaintext.byteOffset,
    plaintext.byteLength,
  ).getUint32(0);

  if (length === 0 || length + 4 > plaintext.length) {
    throw new InvalidPrivateDeliveryError();
  }

  if (plaintext.subarray(length + 4).some((byte) => byte !== 0)) {
    throw new InvalidPrivateDeliveryError();
  }

  return PrivateDeliveryFrame.fromCanonicalJson(
    Buffer.from(plaintext.subarray(4, length + 4)).toString('utf8'),
  );
};

export class PrivateDeliveryEnvelope {
  private static validateHeader(value: PrivateDeliveryHeader): void {
    if (
      !value ||
      value.version !== 1 ||
      !Number.isSafeInteger(value.expiresAt) ||
      value.expiresAt < 0 ||
      !BUCKETS.has(value.bucketBytes)
    ) {
      throw new InvalidPrivateDeliveryError();
    }
    decodeBase64Url(value.mailboxId, 32).fill(0);
    decodeBase64Url(value.deliveryId, 16).fill(0);
  }

  public static headerAad(value: PrivateDeliveryHeader): string {
    try {
      validateHeaderShape(value);
      this.validateHeader(value);

      return canonicalize({
        bucketBytes: value.bucketBytes,
        deliveryId: value.deliveryId,
        expiresAt: value.expiresAt,
        mailboxId: value.mailboxId,
        version: value.version,
      })!;
    } catch {
      throw new InvalidPrivateDeliveryError();
    }
  }

  public static framePlaintext(
    frame: PrivateDeliveryFrame,
    bucketBytes: PrivateDeliveryBucketBytes,
  ): Uint8Array {
    try {
      if (!BUCKETS.has(bucketBytes)) throw new InvalidPrivateDeliveryError();
      const frameBytes = Buffer.from(frame.toCanonicalJson(), 'utf8');
      const plaintextLength = bucketBytes - ENCAPSULATED_KEY_BYTES - TAG_BYTES;

      if (frameBytes.length + 4 > plaintextLength) {
        throw new InvalidPrivateDeliveryError();
      }
      const plaintext = new Uint8Array(plaintextLength);
      new DataView(plaintext.buffer).setUint32(0, frameBytes.length);
      plaintext.set(frameBytes, 4);

      return plaintext;
    } catch {
      throw new InvalidPrivateDeliveryError();
    }
  }

  public static async seal(
    frame: PrivateDeliveryFrame,
    descriptor: PrivateDeliveryDescriptor,
    now: number,
    expiresAt: number,
    bucketBytes: PrivateDeliveryBucketBytes,
  ): Promise<PrivateDeliveryEnvelopeData> {
    try {
      if (!descriptor.acceptsWrite(now, expiresAt)) {
        throw new InvalidPrivateDeliveryError();
      }
      const header: PrivateDeliveryHeader = {
        bucketBytes,
        deliveryId: randomIdentifier(16),
        expiresAt,
        mailboxId: descriptor.mailboxId,
        version: 1,
      };
      const aad = new TextEncoder().encode(this.headerAad(header));
      const plaintext = this.framePlaintext(frame, bucketBytes);
      const publicBytes = decodeBase64Url(descriptor.recipientPublicKey, 32);
      const suite = await getMlsCiphersuite();

      try {
        const publicKey = await suite.hpke.importPublicKey(publicBytes);
        const encrypted = await suite.hpke.seal(
          publicKey,
          plaintext,
          INFO,
          aad,
        );
        const wire = Buffer.concat([
          Buffer.from(encrypted.enc),
          Buffer.from(encrypted.ct),
        ]);

        if (wire.length !== bucketBytes)
          throw new InvalidPrivateDeliveryError();

        return { ...header, ciphertext: wire.toString('base64') };
      } finally {
        aad.fill(0);
        plaintext.fill(0);
        publicBytes.fill(0);
      }
    } catch {
      throw new InvalidPrivateDeliveryError();
    }
  }

  public static async open(
    value: PrivateDeliveryEnvelopeData,
    privateKeyBytes: Uint8Array,
    now: number,
  ): Promise<PrivateDeliveryFrame> {
    try {
      validateEnvelopeShape(value);
      this.validateHeader(value);
      validateOpenInputs(value, privateKeyBytes, now);
      const wire = decodeWire(value);
      const aad = new TextEncoder().encode(
        this.headerAad({
          bucketBytes: value.bucketBytes,
          deliveryId: value.deliveryId,
          expiresAt: value.expiresAt,
          mailboxId: value.mailboxId,
          version: value.version,
        }),
      );
      const suite = await getMlsCiphersuite();
      let plaintext: Uint8Array | undefined;

      try {
        const privateKey = await suite.hpke.importPrivateKey(privateKeyBytes);
        plaintext = await suite.hpke.open(
          privateKey,
          wire.subarray(0, ENCAPSULATED_KEY_BYTES),
          wire.subarray(ENCAPSULATED_KEY_BYTES),
          INFO,
          aad,
        );

        return decodeFrame(plaintext, value.bucketBytes);
      } finally {
        aad.fill(0);
        wire.fill(0);
        plaintext?.fill(0);
      }
    } catch {
      throw new InvalidPrivateDeliveryError();
    }
  }
}
