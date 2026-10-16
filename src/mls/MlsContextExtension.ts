/** One GroupContext extension: its numeric type and its opaque bytes. */
export type MlsContextExtension = Readonly<{
  extensionData: Uint8Array;
  extensionType: number;
}>;
