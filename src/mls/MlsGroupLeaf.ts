import type { MlsLeafOwner } from './MlsLeafOwner';

/** A leaf of an MLS group tree: its index, owner and MLS signature key. */
export interface MlsGroupLeaf {
  readonly index: number;
  readonly owner: MlsLeafOwner;
  readonly signaturePublicKey: Uint8Array;
}
