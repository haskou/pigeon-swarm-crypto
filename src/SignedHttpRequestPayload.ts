export type SignedHttpRequestPayload = Readonly<{
  bodyHash: string;
  method: string;
  path: string;
  timestamp: number;
}>;
