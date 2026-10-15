export type PrivateNetworkRelayRecord = Readonly<{
  expiresAt: number;
  issuedAt: number;
  multiaddrs: readonly string[];
  peerId: string;
  role: 'relay';
  version: 1;
}>;
