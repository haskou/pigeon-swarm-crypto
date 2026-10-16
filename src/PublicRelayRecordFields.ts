export type PublicRelayRecordFields = Readonly<{
  expiresAt: number;
  issuedAt: number;
  multiaddrs: readonly string[];
  peerId: string;
  publicKey: string;
  role: 'relay';
  version: 1;
}>;
