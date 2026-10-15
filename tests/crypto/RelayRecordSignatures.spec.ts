import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from 'node:crypto';

import * as Crypto from '../../src';
import vectors from '../../vectors/relay-records.json';

type CallRecord = Crypto.CallRelayRecordFields & {
  poolSignature: string;
  signature: string;
};
type PublicRecord = Crypto.PublicRelayRecordFields & { signature: string };

const relayKey = createPrivateKey(vectors.keys.relay.privateKeyPem);
const rawPublicKey = createPublicKey(relayKey)
  .export({ format: 'der', type: 'spki' })
  .subarray(-32);
const callInvalid = expect.objectContaining({
  message: 'Invalid call relay record',
  name: 'InvalidCallRelayRecordError',
});
const publicInvalid = expect.objectContaining({
  message: 'Invalid public relay record',
  name: 'InvalidPublicRelayRecordError',
});

describe('CallRelayRecordSignature', () => {
  it('uses the libp2p protobuf encoding of the relay key', () => {
    expect(vectors.keys.relay.publicKey).toBe(
      Buffer.concat([Buffer.from('08011220', 'hex'), rawPublicKey]).toString(
        'base64url',
      ),
    );
  });

  it.each(vectors.cases.map((entry) => [entry.name, entry]))(
    'reproduces and verifies %s',
    (_name, entry) => {
      const record = entry.derived.record as CallRecord;
      const message = Crypto.CallRelayRecordSignature.signingBytes(record);

      expect(Buffer.from(message).toString('utf8')).toBe(
        entry.derived.canonicalPayload,
      );
      expect(
        Crypto.CallRelayRecordSignature.poolSignature(
          record,
          vectors.sharedSecret,
        ),
      ).toBe(entry.derived.poolSignature);
      expect(entry.derived.poolSignature).toBe(
        record.version === 1
          ? createHmac('sha256', vectors.sharedSecret)
              .update(message)
              .digest('base64url')
          : '',
      );
      expect(sign(null, message, relayKey).toString('base64url')).toBe(
        entry.derived.signature,
      );
      expect(() =>
        Crypto.CallRelayRecordSignature.verify(
          record,
          record.poolSignature,
          record.signature,
          vectors.sharedSecret,
        ),
      ).not.toThrow();
    },
  );

  it('sorts urls without mutating the caller record', () => {
    const record = vectors.cases[0].derived.record as CallRecord;
    const reversed = { ...record, urls: [...record.urls].reverse() };

    expect(
      Crypto.CallRelayRecordSignature.signingBytes(Object.freeze(reversed)),
    ).toEqual(Crypto.CallRelayRecordSignature.signingBytes(record));
    expect(reversed.urls).toEqual([...record.urls].reverse());
  });

  it('requires a pool secret to sign v1 announcements', () => {
    const record = vectors.cases[0].derived.record as CallRecord;

    for (const secret of ['', undefined])
      expect(() =>
        Crypto.CallRelayRecordSignature.poolSignature(record, secret as string),
      ).toThrow(callInvalid);
    expect(
      Crypto.CallRelayRecordSignature.poolSignature(
        vectors.cases[1].derived.record as CallRecord,
        '',
      ),
    ).toBe('');
  });

  it.each(vectors.invalidCallRecords.map((entry) => [entry.name, entry]))(
    'rejects %s',
    (_name, entry) => {
      const record = entry.record as CallRecord;

      expect(() =>
        Crypto.CallRelayRecordSignature.verify(
          record,
          record.poolSignature,
          record.signature,
          entry.sharedSecret,
        ),
      ).toThrow(callInvalid);
    },
  );

  it('rejects malformed fields and signatures', () => {
    const record = vectors.cases[1].derived.record as CallRecord;

    for (const fields of [
      undefined,
      null,
      { ...record, issuedAt: '1' },
      { ...record, urls: 'turn:x' },
      { ...record, urls: [''] },
      { ...record, urls: ['a'.repeat(2049)] },
      { ...record, urls: ['\uDC00'] },
      { ...record, publicKey: `${record.publicKey}A` },
    ])
      expect(() =>
        Crypto.CallRelayRecordSignature.signingBytes(
          fields as unknown as CallRecord,
        ),
      ).toThrow(callInvalid);
    for (const [poolSignature, signature] of [
      [undefined, record.signature],
      ['', undefined],
      ['', record.signature.slice(1)],
    ])
      expect(() =>
        Crypto.CallRelayRecordSignature.verify(
          record,
          poolSignature as string,
          signature as string,
          vectors.sharedSecret,
        ),
      ).toThrow(callInvalid);
  });
});

describe('PublicRelayRecordSignature', () => {
  const record = vectors.publicRelay.record as PublicRecord;

  it('reproduces and verifies the shipped public relay record', () => {
    const message = Crypto.PublicRelayRecordSignature.signingBytes(record);

    expect(Buffer.from(message).toString('utf8')).toBe(
      vectors.publicRelay.canonicalPayload,
    );
    expect(
      verify(
        null,
        message,
        createPublicKey(relayKey),
        Buffer.from(record.signature, 'base64url'),
      ),
    ).toBe(true);
    expect(() =>
      Crypto.PublicRelayRecordSignature.verify(record, record.signature),
    ).not.toThrow();
  });

  it.each(vectors.publicRelay.invalid.map((entry) => [entry.name, entry]))(
    'rejects %s',
    (_name, entry) => {
      const invalidRecord = entry.record as PublicRecord;

      expect(() =>
        Crypto.PublicRelayRecordSignature.verify(
          invalidRecord,
          invalidRecord.signature,
        ),
      ).toThrow(publicInvalid);
    },
  );

  it('rejects malformed fields and signatures', () => {
    for (const fields of [
      undefined,
      {
        ...record,
        publicKey: vectors.invalidCallRecords.find(
          (entry) => entry.name === 'small_order_public_key',
        )?.record.publicKey,
      },
      { ...record, multiaddrs: Array(65).fill('/ip4/203.0.113.7/tcp/1') },
      { ...record, peerId: 'Qm0' },
      { ...record, expiresAt: record.issuedAt },
    ])
      expect(() =>
        Crypto.PublicRelayRecordSignature.signingBytes(
          fields as unknown as PublicRecord,
        ),
      ).toThrow(publicInvalid);
    for (const signature of [undefined, '', `${record.signature}A`])
      expect(() =>
        Crypto.PublicRelayRecordSignature.verify(
          record,
          signature as unknown as string,
        ),
      ).toThrow(publicInvalid);
  });
});
