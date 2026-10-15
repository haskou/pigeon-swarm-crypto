import { bytesToHex } from '@noble/hashes/utils.js';

import { CanonicalBase64Url } from './internal/CanonicalBase64Url';
import { PrivateNetworkSecret } from './internal/PrivateNetworkSecret';
import { PrivateKey } from './PrivateKey';

export class PrivateNetworkKeys {
  private static readonly FINGERPRINT_LABEL =
    'pigeon.private-network.fingerprint.v2';

  private static readonly FINGERPRINT_LENGTH = 12;
  private static readonly RELAY_LOOKUP_LABEL =
    'pigeon.private-network.relay-lookup.v2';

  private static readonly RELAY_LOOKUP_PREFIX =
    'pigeon-swarm/private-relays/v2/';

  private static readonly SWARM_KEY_HEADER =
    '/key/swarm/psk/1.0.0/\n/base16/\n';

  private static readonly SWARM_KEY_LABEL =
    'pigeon.private-network.swarm-psk.v2';

  public static fingerprint(networkKey: PrivateKey): string {
    return CanonicalBase64Url.encode(
      PrivateNetworkSecret.derive(
        networkKey,
        this.FINGERPRINT_LABEL,
        this.FINGERPRINT_LENGTH,
      ),
    );
  }

  public static relayLookupKey(networkKey: PrivateKey): string {
    return `${this.RELAY_LOOKUP_PREFIX}${CanonicalBase64Url.encode(
      PrivateNetworkSecret.derive(networkKey, this.RELAY_LOOKUP_LABEL, 32),
    )}`;
  }

  public static swarmKey(networkKey: PrivateKey): Uint8Array {
    return new TextEncoder().encode(
      `${this.SWARM_KEY_HEADER}${bytesToHex(
        PrivateNetworkSecret.derive(networkKey, this.SWARM_KEY_LABEL, 32),
      )}`,
    );
  }
}
