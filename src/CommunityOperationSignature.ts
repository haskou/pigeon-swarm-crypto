import { InvalidCommunityOperationSignatureError } from './errors/InvalidCommunityOperationSignatureError';
import { PreimageFields } from './internal/PreimageFields';
import { PrivateKey } from './PrivateKey';
import { PublicKey } from './PublicKey';
import { Signature } from './Signature';

/**
 * The actor identity signature over one community operation record id. The
 * record id already commits to the community and the operation digest.
 */
export class CommunityOperationSignature {
  private static readonly DOMAIN = 'pigeon:community-operation:v1\n';
  private static readonly RECORD_ID =
    /^community:[A-Za-z0-9_-]{1,128}:op:[A-Za-z0-9_-]{43}$/;

  private static content(recordId: string): string {
    return this.DOMAIN + PreimageFields.pattern(recordId, this.RECORD_ID);
  }

  public static signingContent(recordId: string): string {
    return PreimageFields.guarded(InvalidCommunityOperationSignatureError, () =>
      this.content(recordId),
    );
  }

  public static sign(recordId: string, key: PrivateKey): Signature {
    return PreimageFields.guarded(InvalidCommunityOperationSignatureError, () =>
      key.sign(this.content(recordId)),
    );
  }

  public static verify(
    recordId: string,
    signature: Signature,
    key: PublicKey,
  ): void {
    PreimageFields.guarded(InvalidCommunityOperationSignatureError, () =>
      PreimageFields.verify(this.content(recordId), signature, key),
    );
  }
}
