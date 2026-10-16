const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { createServer } = require('node:http');
const { join } = require('node:path');
const { build } = require('esbuild');
const { chromium } = require('playwright');
const PigeonCrypto = require('../../dist');

const vectorsOf = (name) =>
  JSON.parse(
    readFileSync(
      join(__dirname, '..', '..', 'vectors', `${name}.json`),
      'utf8',
    ),
  );

// Computes every shipped vector in the current runtime, so Node and the browser
// bundle run the exact same code against the same expected bytes.
function computeAll(PigeonCrypto, vectors) {
  const {
    CanonicalJson,
    CommunityInviteReference,
    CommunityOperationSignature,
    DevicePairingCompletionSignature,
    DevicePairingInvitationSignature,
    DevicePairingRequestSignature,
    DevicePairingVerificationCode,
    PrivateFreshnessRequest,
    PrivateKey,
    PublicKey,
    PublicMutationSignature,
    Signature,
    SignedHttpRequestSignature,
  } = PigeonCrypto;
  const rejects = (verify) => {
    try {
      verify();
      return false;
    } catch (error) {
      return error.message.startsWith('Invalid ');
    }
  };
  const http = vectors.http;
  const httpKey = PrivateKey.fromPEM(http.key.privateKeyPem);
  const httpPublicKey = new PublicKey(http.key.publicKeyPem);
  const requestOf = (input) => ({
    body:
      input.bodyBase64 === undefined
        ? (input.bodyText ?? input.body)
        : Uint8Array.from(atob(input.bodyBase64), (char) => char.charCodeAt(0)),
    method: input.method,
    path: input.path,
    timestamp: input.timestamp,
  });
  const pairing = vectors.pairing;
  const pairingFormats = {
    completion: DevicePairingCompletionSignature,
    invitation: DevicePairingInvitationSignature,
    request: DevicePairingRequestSignature,
  };
  const pairingSigners = {
    completion: 'author',
    invitation: 'author',
    request: 'target',
  };
  const community = vectors.community;
  const freshness = vectors.freshness;

  return {
    canonical: vectors.canonical.cases.map(({ value }) =>
      CanonicalJson.serialize(value),
    ),
    http: http.cases.map(({ input, headers }) => {
      const request = requestOf(input);
      SignedHttpRequestSignature.verify(
        request,
        new Signature(headers['x-signature']),
        httpPublicKey,
      );
      return [
        SignedHttpRequestSignature.signingContent(request),
        SignedHttpRequestSignature.sign(request, httpKey).valueOf(),
      ];
    }),
    httpRejected: http.rejected.map(({ input, headers }) =>
      rejects(() =>
        SignedHttpRequestSignature.verify(
          requestOf(input),
          new Signature(headers['x-signature']),
          httpPublicKey,
        ),
      ),
    ),
    pairing: Object.entries(pairingFormats).map(([member, format]) => {
      const { payload, signature } = pairing[member];
      const signer = pairing.keys[pairingSigners[member]];
      format.verify(
        payload,
        new Signature(signature),
        new PublicKey(signer.publicKeyPem),
      );
      return [
        format.signingContent(payload),
        format
          .sign(payload, PrivateKey.fromPEM(signer.privateKeyPem))
          .valueOf(),
      ];
    }),
    pairingRejected: pairing.rejected.map(
      ({ format, payload, signature, signer }) =>
        rejects(() =>
          pairingFormats[format].verify(
            payload,
            new Signature(signature),
            new PublicKey(pairing.keys[signer].publicKeyPem),
          ),
        ),
    ),
    codes: pairing.verificationCodes.map(({ input }) =>
      DevicePairingVerificationCode.of(input),
    ),
    mutations: vectors.calls.cases.map(({ derived }) => {
      const signer = Object.values(vectors.calls.keys).find(
        ({ identityId }) =>
          identityId === derived.mutationBody.author.deviceCredential,
      );
      const verified = PublicMutationSignature.verify(
        derived.mutation,
        new PublicKey(signer.publicKeyPem),
      );
      return [
        PublicMutationSignature.payloadDigest(derived.payload),
        PublicMutationSignature.signingContent(derived.mutationBody),
        PublicMutationSignature.sign(
          derived.mutationBody,
          PrivateKey.fromPEM(signer.privateKeyPem),
        ).signature,
        PublicMutationSignature.digest(verified),
      ];
    }),
    mutationTamperRejected: rejects(() => {
      const [{ derived }] = vectors.calls.cases;
      const signer = Object.values(vectors.calls.keys).find(
        ({ identityId }) =>
          identityId === derived.mutationBody.author.deviceCredential,
      );
      PublicMutationSignature.verify(
        { ...derived.mutation, sequence: derived.mutation.sequence + 1 },
        new PublicKey(signer.publicKeyPem),
      );
    }),
    community: community.cases.map(({ derived, input }) => [
      CommunityOperationSignature.signingContent(derived.recordId),
      CommunityOperationSignature.sign(
        derived.recordId,
        PrivateKey.fromPEM(community.keys[input.signer].privateKeyPem),
      ).valueOf(),
    ]),
    inviteReference: CommunityInviteReference.of(community.inviteToken.token),
    freshness: freshness.cases.map(({ input }) =>
      PrivateFreshnessRequest.serialize(input),
    ),
  };
}

const expected = (vectors) => ({
  canonical: vectors.canonical.cases.map(({ canonical }) => canonical),
  http: vectors.http.cases.map(({ derived }) => [
    derived.signingContent,
    derived.signature,
  ]),
  httpRejected: vectors.http.rejected.map(() => true),
  pairing: ['completion', 'invitation', 'request'].map((member) => [
    vectors.pairing[member].signingPayload,
    vectors.pairing[member].signature,
  ]),
  pairingRejected: vectors.pairing.rejected.map(() => true),
  codes: vectors.pairing.verificationCodes.map(({ code }) => code),
  mutations: vectors.calls.cases.map(({ derived }) => [
    derived.payloadDigest,
    derived.signingContent,
    derived.signature,
    PigeonCrypto.PublicMutationSignature.digest(derived.mutation),
  ]),
  mutationTamperRejected: true,
  community: vectors.community.cases.map(({ derived }) => [
    derived.identitySigningContent,
    derived.identitySignature,
  ]),
  inviteReference: vectors.community.inviteToken.reference,
  freshness: vectors.freshness.cases.map(({ requestJson }) => requestJson),
});

(async () => {
  const vectors = {
    calls: vectorsOf('call-event'),
    canonical: vectorsOf('canonical-json'),
    community: vectorsOf('community-operation'),
    freshness: vectorsOf('private-freshness-request'),
    http: vectorsOf('signed-http-request'),
    pairing: vectorsOf('device-pairing'),
  };
  const want = expected(vectors);
  assert.deepEqual(computeAll(PigeonCrypto, vectors), want);
  const bundle = await build({
    stdin: {
      contents: "export * from './dist/index.js';",
      resolveDir: process.cwd(),
    },
    bundle: true,
    format: 'iife',
    globalName: 'PigeonCrypto',
    platform: 'browser',
    write: false,
  });
  const server = createServer((request, response) => {
    response.setHeader('Content-Type', 'text/html');
    response.end(
      '<!doctype html><title>Disposable signed preimage interoperability test</title>',
    );
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    page.on('pageerror', (error) => console.error(error.message));
    await page.goto('http://127.0.0.1:' + server.address().port);
    await page.addScriptTag({ content: bundle.outputFiles[0].text });
    const browserResult = await page.evaluate(
      ({ source, vectors }) =>
        new Function('return ' + source)()(PigeonCrypto, vectors),
      { source: computeAll.toString(), vectors },
    );
    assert.deepEqual(browserResult, want);
    console.log(
      'PASS Node and bundled Chromium reproduce every signed preimage vector; tampering and cross-domain reuse are rejected.',
    );
  } finally {
    await browser?.close();
    await new Promise((resolve) => server.close(resolve));
  }
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
