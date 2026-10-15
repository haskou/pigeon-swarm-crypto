import type { SignedHttpRequestBody } from './SignedHttpRequestBody';

export type SignedHttpRequest = Readonly<{
  body?: SignedHttpRequestBody;
  method: string;
  path: string;
  timestamp: number;
}>;
