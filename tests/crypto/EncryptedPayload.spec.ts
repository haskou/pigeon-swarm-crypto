import { NullObject, StringValueObject } from '@haskou/value-objects';

import {
  AsymmetricEncryptedPayload,
  EncryptedPayload,
  SymmetricEncryptedPayload,
} from '../../src';

describe('EncryptedPayload', () => {
  describe('constructor', () => {
    it('should return a NullValueObject when receiving nullish', () => {
      const payload = new EncryptedPayload(undefined as unknown as string);
      expect(NullObject.isNullObject(payload)).toBeTrue();
    });

    it('should store a string value verbatim', () => {
      const payload = new EncryptedPayload('some-data');
      expect(payload.isEqual('some-data')).toBeTrue();
      expect(payload.toString()).toBe('some-data');
    });
  });

  describe('getScheme', () => {
    it('should identify legacy asymmetric payloads', () => {
      expect(new EncryptedPayload('eph.iv.cipher.tag').getScheme()).toBe(
        'asymmetric',
      );
    });

    it('should identify versioned asymmetric payloads', () => {
      expect(
        new EncryptedPayload(
          'v2.x25519-hkdf-sha256-aes-256-gcm.eph.iv.cipher.tag',
        ).getScheme(),
      ).toBe('asymmetric');
    });

    it('should identify symmetric payloads', () => {
      expect(
        new EncryptedPayload('v1.aes-256-gcm.iv.cipher.tag').getScheme(),
      ).toBe('symmetric');
    });

    it('should return unknown for unsupported payload formats', () => {
      expect(new EncryptedPayload('some-data').getScheme()).toBe('unknown');
    });

    it('should return unknown for incomplete symmetric payload formats', () => {
      expect(new EncryptedPayload('v1.aes-256-gcm').getScheme()).toBe('unknown');
    });

    it('should allow subclasses to expose their fixed scheme', () => {
      const asymmetric = new AsymmetricEncryptedPayload('some-data');
      const symmetric = new SymmetricEncryptedPayload('some-data');

      expect(asymmetric).toBeInstanceOf(EncryptedPayload);
      expect(symmetric).toBeInstanceOf(EncryptedPayload);
      expect(asymmetric.getScheme()).toBe('asymmetric');
      expect(symmetric.getScheme()).toBe('symmetric');
    });
  });

  describe('ValueObject behavior', () => {
    it('should expose value, string, equality and cloning', () => {
      const payload = new EncryptedPayload('encrypted');
      const equal = new EncryptedPayload('encrypted');
      const different = new EncryptedPayload('different');
      const cloned = (payload as any).clone();

      expect(payload.valueOf()).toBe('encrypted');
      expect(payload.toString()).toBe('encrypted');
      expect(payload.isEqual(equal)).toBeTrue();
      expect(payload.isEqual(different)).toBeFalse();
      expect(payload.isEqual('encrypted')).toBeTrue();
      expect(payload.isEqual('different')).toBeFalse();
      expect(cloned).toBeInstanceOf(EncryptedPayload);
      expect(cloned.valueOf()).toBe('encrypted');
      expect(cloned).not.toBe(payload);
    });

    it('should accept StringValueObject through ValueObject semantics', () => {
      const value = new StringValueObject('secret');
      expect(new EncryptedPayload(value.valueOf()).isEqual('secret')).toBeTrue();
    });
  });
});
