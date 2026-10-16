import { createHmac } from 'node:crypto';

import * as Crypto from '../../src';
import vectors from '../../vectors/turn-credentials.json';

const invalid = expect.objectContaining({
  message: 'Invalid TURN credential',
  name: 'InvalidTurnCredentialError',
});

describe('TurnRestCredential', () => {
  it.each(vectors.credentials.map((entry) => [entry.name, entry]))(
    'issues %s like an independent HMAC-SHA1',
    (_name, entry) => {
      const issued = Crypto.TurnRestCredential.issue(
        entry.sharedSecret,
        entry.expiresAtSeconds,
        entry.user,
      );

      expect(issued).toEqual({
        credential: entry.credential,
        username: entry.username,
      });
      expect(issued.credential).toBe(
        createHmac('sha1', entry.sharedSecret)
          .update(`${entry.expiresAtSeconds}:${entry.user}`)
          .digest('base64'),
      );
      expect(Object.isFrozen(issued)).toBe(true);
    },
  );

  it.each(vectors.peerSubjects.map((entry) => [entry.name, entry]))(
    'derives the %s subject like an independent HMAC-SHA256',
    (_name, entry) => {
      expect(
        Crypto.TurnRestCredential.peerSubject(entry.sharedSecret, entry.peerId),
      ).toBe(entry.subject);
      expect(entry.subject).toBe(
        createHmac('sha256', entry.sharedSecret)
          .update(`pigeon.turn.subject.v2\0${entry.peerId}`)
          .digest('hex')
          .slice(0, 32),
      );
    },
  );

  it.each(vectors.invalidCredentials.map((entry) => [entry.name, entry]))(
    'rejects credential %s',
    (_name, entry) => {
      expect(() =>
        Crypto.TurnRestCredential.issue(
          entry.sharedSecret,
          entry.expiresAtSeconds,
          entry.user,
        ),
      ).toThrow(invalid);
    },
  );

  it.each(vectors.invalidPeerSubjects.map((entry) => [entry.name, entry]))(
    'rejects peer subject %s',
    (_name, entry) => {
      expect(() =>
        Crypto.TurnRestCredential.peerSubject(entry.sharedSecret, entry.peerId),
      ).toThrow(invalid);
    },
  );

  it('rejects non-string inputs and oversized or ill-formed secrets', () => {
    for (const secret of [undefined, 1, 'a'.repeat(4097), 'a\uD800'])
      expect(() =>
        Crypto.TurnRestCredential.issue(secret as string, 1, 'user'),
      ).toThrow(invalid);
    expect(() =>
      Crypto.TurnRestCredential.issue('secret', '1' as unknown as number, 'u'),
    ).toThrow(invalid);
    expect(() =>
      Crypto.TurnRestCredential.issue('secret', 1, 1 as unknown as string),
    ).toThrow(invalid);
    expect(() =>
      Crypto.TurnRestCredential.peerSubject(
        'secret',
        undefined as unknown as string,
      ),
    ).toThrow(invalid);
    expect(
      Crypto.TurnRestCredential.issue('a'.repeat(4096), 1, 'b'.repeat(512))
        .username,
    ).toBe(`1:${'b'.repeat(512)}`);
    expect(
      Crypto.TurnRestCredential.peerSubject('s', '~'.repeat(256)),
    ).toHaveLength(32);
  });
});
