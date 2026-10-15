import { InvalidPrivateNetworkMessageError } from './errors/InvalidPrivateNetworkMessageError';
import { PrivateNetworkSealedEnvelope } from './internal/PrivateNetworkSealedEnvelope';
import { PrivateNetworkSecret } from './internal/PrivateNetworkSecret';
import { PrivateKey } from './PrivateKey';

export class PrivateNetworkPubSubEnvelope {
  private static readonly KEY_LABEL = 'pigeon.private-network.pubsub.v2';
  private static readonly MAX_NAME_LENGTH = 1024;
  private static readonly MAX_PAYLOAD_LENGTH = 1048576;

  private static aad(networkId: unknown, topic: unknown): Uint8Array {
    if (!this.isName(networkId) || !this.isName(topic))
      throw new InvalidPrivateNetworkMessageError();

    return new TextEncoder().encode(
      `${this.KEY_LABEL}\0${JSON.stringify({ networkId, topic })}`,
    );
  }

  private static isName(value: unknown): value is string {
    return (
      typeof value === 'string' &&
      value.length > 0 &&
      value.length <= this.MAX_NAME_LENGTH &&
      !/[\uD800-\uDFFF]/u.test(value)
    );
  }

  public static open(
    networkKey: PrivateKey,
    networkId: string,
    topic: string,
    envelope: string,
  ): string {
    const aad = this.aad(networkId, topic);
    const key = PrivateNetworkSecret.derive(networkKey, this.KEY_LABEL, 32);

    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(
        PrivateNetworkSealedEnvelope.open(
          key,
          aad,
          envelope,
          this.MAX_PAYLOAD_LENGTH,
        ),
      );
    } catch {
      throw new InvalidPrivateNetworkMessageError();
    }
  }

  public static seal(
    networkKey: PrivateKey,
    networkId: string,
    topic: string,
    payload: string,
  ): string {
    const aad = this.aad(networkId, topic);

    if (typeof payload !== 'string' || /[\uD800-\uDFFF]/u.test(payload))
      throw new InvalidPrivateNetworkMessageError();
    const plaintext = new TextEncoder().encode(payload);

    if (plaintext.length > this.MAX_PAYLOAD_LENGTH)
      throw new InvalidPrivateNetworkMessageError();

    return PrivateNetworkSealedEnvelope.seal(
      PrivateNetworkSecret.derive(networkKey, this.KEY_LABEL, 32),
      aad,
      plaintext,
    );
  }
}
