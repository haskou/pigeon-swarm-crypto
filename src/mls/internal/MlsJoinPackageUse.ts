import { KeyPackage, PrivateKeyPackage } from 'ts-mls';

export const MLS_JOIN_PACKAGE_USE: unique symbol = Symbol(
  'pigeon.mls-join-package-use',
);

export type MlsJoinPackageOperation<T> = (
  publicPackage: KeyPackage,
  privatePackage: PrivateKeyPackage,
) => Promise<T>;
