import { CanonicalJson } from '../CanonicalJson';
import { InvalidDevicePairingError } from '../errors/InvalidDevicePairingError';
import { PrivateKey } from '../PrivateKey';
import { PublicKey } from '../PublicKey';
import { Signature } from '../Signature';
import { PreimageFields } from './PreimageFields';

/**
 * One signed device pairing message: `{domain, <member>: payload}` in
 * canonical JSON, signed by the PEM credential the payload names.
 */
export class DevicePairingPreimage<T extends object> {
  public constructor(
    private readonly domain: string,
    private readonly member: string,
    private readonly signerField: keyof T & string,
    private readonly read: (record: Record<string, unknown>) => T,
  ) {}

  private content(payload: T): string {
    return CanonicalJson.serialize({
      domain: this.domain,
      [this.member]: this.read(payload as Record<string, unknown>),
    });
  }

  private signer(payload: T): string {
    return PreimageFields.credentialBody(
      new PublicKey(payload[this.signerField] as string),
    );
  }

  public signingContent(payload: T): string {
    return PreimageFields.guarded(InvalidDevicePairingError, () =>
      this.content(payload),
    );
  }

  public sign(payload: T, key: PrivateKey): Signature {
    return PreimageFields.guarded(InvalidDevicePairingError, () =>
      PreimageFields.signFor(this.content(payload), key, this.signer(payload)),
    );
  }

  public verify(payload: T, signature: Signature, key: PublicKey): void {
    PreimageFields.guarded(InvalidDevicePairingError, () =>
      PreimageFields.verifyFor(
        this.content(payload),
        signature,
        key,
        this.signer(payload),
      ),
    );
  }
}
