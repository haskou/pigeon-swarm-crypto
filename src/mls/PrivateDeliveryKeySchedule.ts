import { x25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { Buffer } from 'buffer';
import canonicalize from 'canonicalize';

import { CryptoAdapter } from '../internal/CryptoAdapter';
import { UserRootKey } from '../UserRootKey';
import { DeliveryBase64Url } from './internal/DeliveryBase64Url';
import { getMlsCiphersuite } from './internal/MlsRuntime';
import { InvalidPrivateDeliveryError } from './InvalidPrivateDeliveryError';
import { PrivateDeliveryDescriptor } from './PrivateDeliveryDescriptor';
import { PrivateDeliveryEnvelope } from './PrivateDeliveryEnvelope';
import { PrivateDeliveryEnvelopeData } from './PrivateDeliveryEnvelopeData';
import { PrivateDeliveryFrame } from './PrivateDeliveryFrame';
import { PrivateDeliveryScheduleEntry } from './PrivateDeliveryScheduleEntry';
import { PrivateDeliveryScheduleState } from './PrivateDeliveryScheduleState';
import { ProtectedPrivateDeliveryKeySchedule } from './ProtectedPrivateDeliveryKeySchedule';

const DAY_MS = 24 * 60 * 60 * 1000;
const SCHEDULE_DAYS = 8;
const MAX_RETENTION_MS = 30 * DAY_MS;

const randomMailboxId = (): string => {
  const value = CryptoAdapter.randomBytes(32);

  try {
    return DeliveryBase64Url.encode(value);
  } finally {
    value.fill(0);
  }
};

const commitmentFor = (
  entries: readonly PrivateDeliveryScheduleEntry[],
): string =>
  DeliveryBase64Url.encode(
    sha256(
      Buffer.from(
        canonicalize({
          descriptors: entries.map((entry) => entry.descriptor.toJSON()),
          version: 1,
        })!,
        'utf8',
      ),
    ),
  );

const startOfUtcDay = (timestamp: number): number => {
  if (!Number.isSafeInteger(timestamp) || timestamp < 0) {
    throw new InvalidPrivateDeliveryError();
  }
  const value = new Date(timestamp);

  return Date.UTC(
    value.getUTCFullYear(),
    value.getUTCMonth(),
    value.getUTCDate(),
  );
};

const parseScheduleState = (
  plaintext: Uint8Array,
): PrivateDeliveryScheduleState => {
  const json = Buffer.from(plaintext).toString('utf8');
  const value = JSON.parse(json) as PrivateDeliveryScheduleState;

  if (
    Object.keys(value).sort().join(',') !== 'entries,version' ||
    value.version !== 1 ||
    !Array.isArray(value.entries)
  ) {
    throw new InvalidPrivateDeliveryError();
  }

  if (value.entries.length > SCHEDULE_DAYS) {
    throw new InvalidPrivateDeliveryError();
  }

  if (canonicalize(value) !== json) throw new InvalidPrivateDeliveryError();

  if (
    value.entries.some(
      (entry) =>
        !entry ||
        Object.keys(entry).sort().join(',') !== 'descriptor,privateKey',
    )
  ) {
    throw new InvalidPrivateDeliveryError();
  }

  return value;
};

const restoreEntry = async (
  stored: PrivateDeliveryScheduleState['entries'][number],
): Promise<PrivateDeliveryScheduleEntry> => {
  const descriptor = PrivateDeliveryDescriptor.from(stored.descriptor);
  const privateKey = Buffer.from(stored.privateKey, 'base64');

  try {
    if (
      privateKey.length !== 32 ||
      privateKey.toString('base64') !== stored.privateKey
    ) {
      throw new InvalidPrivateDeliveryError();
    }
    const suite = await getMlsCiphersuite();

    if (
      DeliveryBase64Url.encode(x25519.getPublicKey(privateKey)) !==
      descriptor.recipientPublicKey
    ) {
      throw new InvalidPrivateDeliveryError();
    }
    await suite.hpke.importPrivateKey(privateKey);

    return { descriptor, privateKey: new Uint8Array(privateKey) };
  } finally {
    privateKey.fill(0);
  }
};

export class PrivateDeliveryKeySchedule {
  #destroyed = false;

  readonly #entries: PrivateDeliveryScheduleEntry[];

  public static async generate(
    now: number,
    authorizationRevision: number,
    maximumRetentionMs: number,
  ): Promise<PrivateDeliveryKeySchedule> {
    const entries: PrivateDeliveryScheduleEntry[] = [];

    try {
      if (
        !Number.isSafeInteger(authorizationRevision) ||
        authorizationRevision < 0 ||
        !Number.isSafeInteger(maximumRetentionMs) ||
        maximumRetentionMs < 0 ||
        maximumRetentionMs > MAX_RETENTION_MS
      ) {
        throw new InvalidPrivateDeliveryError();
      }
      const firstDay = startOfUtcDay(now);
      const suite = await getMlsCiphersuite();
      for (let index = 0; index < SCHEDULE_DAYS; index += 1) {
        const validFrom = firstDay + index * DAY_MS;
        const writeValidUntil = validFrom + DAY_MS;
        const pair = await suite.hpke.generateKeyPair();
        const publicKey = await suite.hpke.exportPublicKey(pair.publicKey);
        const privateKey = await suite.hpke.exportPrivateKey(pair.privateKey);
        entries.push({
          descriptor: PrivateDeliveryDescriptor.from({
            authorizationRevision,
            mailboxId: randomMailboxId(),
            maxCiphertextExpiresAt: writeValidUntil + maximumRetentionMs,
            recipientPublicKey: DeliveryBase64Url.encode(publicKey),
            validFrom,
            version: 1,
            writeValidUntil,
          }),
          privateKey: new Uint8Array(privateKey),
        });
        privateKey.fill(0);
      }

      return new PrivateDeliveryKeySchedule(entries);
    } catch {
      entries.forEach((entry) => entry.privateKey.fill(0));
      throw new InvalidPrivateDeliveryError();
    }
  }

  public static async restore(
    protectedSchedule: ProtectedPrivateDeliveryKeySchedule,
    rootKey: UserRootKey,
    expectedCommitment: string,
  ): Promise<PrivateDeliveryKeySchedule> {
    const plaintext = protectedSchedule.unlock(rootKey);
    const entries: PrivateDeliveryScheduleEntry[] = [];

    try {
      const value = parseScheduleState(plaintext);
      for (const stored of value.entries) {
        entries.push(await restoreEntry(stored));
      }

      if (commitmentFor(entries) !== expectedCommitment) {
        throw new InvalidPrivateDeliveryError();
      }

      return new PrivateDeliveryKeySchedule(entries);
    } catch {
      entries.forEach((entry) => entry.privateKey.fill(0));
      throw new InvalidPrivateDeliveryError();
    } finally {
      plaintext.fill(0);
    }
  }

  private constructor(entries: PrivateDeliveryScheduleEntry[]) {
    this.#entries = entries;
  }

  private ensureActive(): void {
    if (this.#destroyed) throw new InvalidPrivateDeliveryError();
  }

  private transition(
    retained: PrivateDeliveryScheduleEntry[],
  ): PrivateDeliveryKeySchedule {
    this.ensureActive();
    const copied = retained.map((entry) => ({
      descriptor: entry.descriptor,
      privateKey: new Uint8Array(entry.privateKey),
    }));
    this.destroy();

    return new PrivateDeliveryKeySchedule(copied);
  }

  public get descriptors(): PrivateDeliveryDescriptor[] {
    this.ensureActive();

    return this.#entries.map((entry) => entry.descriptor);
  }

  public get commitment(): string {
    this.ensureActive();

    return commitmentFor(this.#entries);
  }

  public descriptorFor(now: number): PrivateDeliveryDescriptor {
    this.ensureActive();
    const descriptor = this.#entries.find(
      (entry) =>
        now >= entry.descriptor.validFrom &&
        now < entry.descriptor.writeValidUntil,
    )?.descriptor;

    if (!descriptor) throw new InvalidPrivateDeliveryError();

    return descriptor;
  }

  public async open(
    envelope: PrivateDeliveryEnvelopeData,
    now: number,
  ): Promise<PrivateDeliveryFrame> {
    this.ensureActive();
    const entry = this.#entries.find(
      (candidate) => candidate.descriptor.mailboxId === envelope.mailboxId,
    );

    if (
      !entry ||
      now > entry.descriptor.maxCiphertextExpiresAt ||
      envelope.expiresAt > entry.descriptor.maxCiphertextExpiresAt
    ) {
      throw new InvalidPrivateDeliveryError();
    }

    return PrivateDeliveryEnvelope.open(envelope, entry.privateKey, now);
  }

  public protect(rootKey: UserRootKey): ProtectedPrivateDeliveryKeySchedule {
    this.ensureActive();
    const state: PrivateDeliveryScheduleState = {
      entries: this.#entries.map((entry) => ({
        descriptor: entry.descriptor.toJSON(),
        privateKey: Buffer.from(entry.privateKey).toString('base64'),
      })),
      version: 1,
    };
    const plaintext = Buffer.from(canonicalize(state)!, 'utf8');

    try {
      return ProtectedPrivateDeliveryKeySchedule.protect(plaintext, rootKey);
    } finally {
      plaintext.fill(0);
    }
  }

  public retire(now: number): PrivateDeliveryKeySchedule {
    return this.transition(
      this.#entries.filter(
        (entry) => now <= entry.descriptor.maxCiphertextExpiresAt,
      ),
    );
  }

  public revoke(mailboxIds: readonly string[]): PrivateDeliveryKeySchedule {
    this.ensureActive();
    const revoked = new Set(mailboxIds);

    if (revoked.size !== mailboxIds.length)
      throw new InvalidPrivateDeliveryError();
    for (const mailboxId of revoked) {
      if (
        !this.#entries.some((entry) => entry.descriptor.mailboxId === mailboxId)
      ) {
        throw new InvalidPrivateDeliveryError();
      }
    }

    return this.transition(
      this.#entries.filter((entry) => !revoked.has(entry.descriptor.mailboxId)),
    );
  }

  public destroy(): void {
    if (this.#destroyed) return;
    this.#entries.forEach((entry) => entry.privateKey.fill(0));
    this.#destroyed = true;
  }
}
