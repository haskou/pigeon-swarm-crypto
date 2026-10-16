import { InvalidPrivateNetworkRelayRecordError } from './errors/InvalidPrivateNetworkRelayRecordError';
import { PrivateNetworkSealedEnvelope } from './internal/PrivateNetworkSealedEnvelope';
import { PrivateNetworkSecret } from './internal/PrivateNetworkSecret';
import { RelayRecordEncoding } from './internal/RelayRecordEncoding';
import { StrictCanonicalJson } from './internal/StrictCanonicalJson';
import { PrivateKey } from './PrivateKey';
import { PrivateNetworkRelayRecord } from './PrivateNetworkRelayRecord';

export class PrivateNetworkRelayRecordEnvelope {
  private static readonly FIELDS =
    'expiresAt,issuedAt,multiaddrs,peerId,role,version';

  private static readonly KEY_LABEL = 'pigeon.private-network.relay-record.v2';

  private static readonly MAX_MULTIADDRS = 32;

  private static readonly MAX_PLAINTEXT_LENGTH = 8192;

  private static isRecord(value: unknown): value is PrivateNetworkRelayRecord {
    if (typeof value !== 'object' || value === null) return false;
    const record = value as Record<string, unknown>;

    return (
      Object.keys(record).sort().join(',') === this.FIELDS &&
      RelayRecordEncoding.isLifetime(record.issuedAt, record.expiresAt) &&
      RelayRecordEncoding.isAddressList(
        record.multiaddrs,
        this.MAX_MULTIADDRS,
      ) &&
      RelayRecordEncoding.isPeerId(record.peerId) &&
      record.role === 'relay' &&
      record.version === 1
    );
  }

  private static toRecord(value: unknown): PrivateNetworkRelayRecord {
    if (!this.isRecord(value))
      throw new InvalidPrivateNetworkRelayRecordError();

    return Object.freeze({
      expiresAt: value.expiresAt,
      issuedAt: value.issuedAt,
      multiaddrs: Object.freeze([...value.multiaddrs]),
      peerId: value.peerId,
      role: value.role,
      version: value.version,
    });
  }

  public static open(
    networkKey: PrivateKey,
    envelope: string,
  ): PrivateNetworkRelayRecord {
    const key = PrivateNetworkSecret.derive(networkKey, this.KEY_LABEL, 32);

    try {
      const plaintext = new TextDecoder('utf-8', { fatal: true }).decode(
        PrivateNetworkSealedEnvelope.open(
          key,
          new TextEncoder().encode(this.KEY_LABEL),
          envelope,
          this.MAX_PLAINTEXT_LENGTH,
        ),
      );
      const value = StrictCanonicalJson.parse(plaintext);

      if (StrictCanonicalJson.serialize(value) !== plaintext)
        throw new InvalidPrivateNetworkRelayRecordError();

      return this.toRecord(value);
    } catch {
      throw new InvalidPrivateNetworkRelayRecordError();
    }
  }

  public static seal(
    networkKey: PrivateKey,
    record: PrivateNetworkRelayRecord,
  ): string {
    const plaintext = new TextEncoder().encode(
      StrictCanonicalJson.serialize(this.toRecord(record)),
    );

    if (plaintext.length > this.MAX_PLAINTEXT_LENGTH)
      throw new InvalidPrivateNetworkRelayRecordError();

    return PrivateNetworkSealedEnvelope.seal(
      PrivateNetworkSecret.derive(networkKey, this.KEY_LABEL, 32),
      new TextEncoder().encode(this.KEY_LABEL),
      plaintext,
    );
  }
}
