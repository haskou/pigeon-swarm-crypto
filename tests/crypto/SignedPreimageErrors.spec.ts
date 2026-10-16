import {
  InvalidCanonicalJsonError,
  InvalidCommunityInviteReferenceError,
  InvalidCommunityOperationSignatureError,
  InvalidDeviceAuthorizationTransitionError,
  InvalidDevicePairingError,
  InvalidDeviceSealedSecretError,
  InvalidIdentitySignatureError,
  InvalidKeychainSignatureError,
  InvalidPrivateFreshnessRequestError,
  InvalidPublicMutationError,
  InvalidSignedHttpRequestError,
} from '../../src';

describe('signed preimage errors', () => {
  it.each([
    [InvalidCanonicalJsonError, 'Invalid canonical JSON'],
    [
      InvalidCommunityInviteReferenceError,
      'Invalid community invite reference',
    ],
    [
      InvalidCommunityOperationSignatureError,
      'Invalid community operation signature',
    ],
    [
      InvalidDeviceAuthorizationTransitionError,
      'Invalid device authorization transition',
    ],
    [InvalidDevicePairingError, 'Invalid device pairing'],
    [InvalidDeviceSealedSecretError, 'Invalid device sealed secret'],
    [InvalidIdentitySignatureError, 'Invalid identity signature'],
    [InvalidKeychainSignatureError, 'Invalid keychain signature'],
    [InvalidPrivateFreshnessRequestError, 'Invalid private freshness request'],
    [InvalidPublicMutationError, 'Invalid public mutation'],
    [InvalidSignedHttpRequestError, 'Invalid signed HTTP request'],
  ])('%p carries a fixed name and message', (ErrorClass, message) => {
    const error = new ErrorClass();

    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe(ErrorClass.name);
    expect(error.message).toBe(message);
  });
});
