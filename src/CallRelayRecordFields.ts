export type CallRelayRecordFields = Readonly<{
  expiresAt: number;
  issuedAt: number;
  peerId: string;
  publicKey: string;
  role: 'call-relay';
  urls: readonly string[];
  version: 1 | 2;
}>;
