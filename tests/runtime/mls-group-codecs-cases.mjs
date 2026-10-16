// Checks the shipped MLS codec vectors; shared by the Node and Chromium runs
// of mls-group-codecs.cjs. Returns how many vectors it checked.

const fail = (label) => {
  throw new Error('FAIL ' + label);
};
const comparable = (value) =>
  JSON.stringify(value, (_key, item) =>
    item instanceof Uint8Array ? Array.from(item) : item,
  );
const same = (actual, expected, label) => {
  if (comparable(actual) !== comparable(expected)) fail(label);
};
const throws = (work, name, message, label) => {
  try {
    work();
  } catch (error) {
    if (error.name !== name || error.message !== message) fail(label);
    return;
  }
  fail(label + ': accepted');
};
const bytesOf = (base64Url) =>
  Uint8Array.from(
    atob(
      base64Url.replace(/-/g, '+').replace(/_/g, '/') +
        '='.repeat((4 - (base64Url.length % 4)) % 4),
    ),
    (character) => character.charCodeAt(0),
  );
const pem = (body) =>
  `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----\n`;

export function run({ KeyPair, mls }, vectors) {
  const {
    GroupMailboxRosterExtension,
    MlsLeafCredential,
    MlsLeafSigner,
    MlsRosterFrontier,
  } = mls;
  const credential = (work, label) =>
    throws(work, 'InvalidMlsCredentialError', 'Invalid MLS credential', label);
  const extension = (work, label) =>
    throws(work, 'InvalidMlsExtensionError', 'Invalid MLS extension', label);
  const { frontier, leaf, roster } = vectors;
  let checked = 0;

  for (const vector of leaf.valid) {
    const signer = new MlsLeafSigner(
      vector.owner,
      KeyPair.fromPrimitives({
        privateKey: leaf.keys.identityPrivateKey,
        publicKey: pem(vector.owner.identityId),
      }),
      KeyPair.fromPrimitives({
        privateKey: leaf.keys.devicePrivateKey,
        publicKey: vector.owner.deviceCredential,
      }),
    );
    const signatureKey = bytesOf(vector.signaturePublicKey);
    const identity = bytesOf(vector.identity);

    same(MlsLeafCredential.issue(signer, signatureKey), identity, vector.name);
    same(MlsLeafCredential.verify(identity, signatureKey), vector.owner, vector.name);
    same(MlsLeafCredential.ownerOf(identity), vector.owner, vector.name);
    checked++;
  }
  for (const vector of leaf.invalid) {
    const identity = bytesOf(vector.identity);

    credential(
      () => MlsLeafCredential.verify(identity, bytesOf(vector.signaturePublicKey)),
      vector.name,
    );
    if (vector.owner)
      same(MlsLeafCredential.ownerOf(identity), vector.owner, vector.name);
    else credential(() => MlsLeafCredential.ownerOf(identity), vector.name);
    checked++;
  }

  for (const vector of frontier.valid) {
    const encoded = bytesOf(vector.encoded);

    same(MlsRosterFrontier.encode(vector.input ?? vector.frontier), encoded, vector.name);
    same(MlsRosterFrontier.decode(encoded), vector.frontier, vector.name);
    checked++;
  }
  for (const vector of frontier.invalid) {
    extension(() => MlsRosterFrontier.decode(bytesOf(vector.encoded)), vector.name);
    checked++;
  }
  const [head] = frontier.valid[1].frontier;
  const heads = frontier.valid[3].frontier;
  extension(() => MlsRosterFrontier.encode([head, head]), 'encode duplicate');
  extension(() => MlsRosterFrontier.encode([head + '=']), 'encode padded');
  extension(
    () => MlsRosterFrontier.encode([...heads, 'z'.repeat(42) + 'A']),
    'encode 257 heads',
  );
  extension(
    () => MlsRosterFrontier.decode(new Uint8Array(11293).fill(0x41)),
    'decode oversized',
  );

  const extensionType = GroupMailboxRosterExtension.EXTENSION_TYPE;
  for (const vector of roster.valid) {
    const encoded = bytesOf(vector.encoded);

    same(
      GroupMailboxRosterExtension.encode(vector.input ?? vector.fields),
      encoded,
      vector.name,
    );
    same(GroupMailboxRosterExtension.decode(encoded), vector.fields, vector.name);
    same(
      GroupMailboxRosterExtension.read([{ extensionData: encoded, extensionType }]),
      vector.fields,
      vector.name,
    );
    checked++;
  }
  for (const vector of roster.invalid) {
    extension(
      () => GroupMailboxRosterExtension.decode(bytesOf(vector.encoded)),
      vector.name,
    );
    checked++;
  }
  const { fields } = roster.valid[0];
  const extensionData = bytesOf(roster.valid[0].encoded);
  const entry = { extensionData, extensionType };
  for (const [label, invalid] of [
    ['encode version 2', { ...fields, version: 2 }],
    ['encode creator as admin', { ...fields, adminIds: [fields.creatorId] }],
    ['encode extra key', { ...fields, extra: true }],
    ['encode long name', { ...fields, name: 'n'.repeat(81) }],
    ['encode long id', { ...fields, adminIds: ['i'.repeat(1025)], memberIds: [...fields.memberIds, 'i'.repeat(1025)] }],
    ['encode members not a list', { ...fields, memberIds: 'alice' }],
    ['encode 257 admins', { ...fields, adminIds: Array.from({ length: 257 }, (_, index) => 'a' + index) }],
    ['encode null', null],
  ])
    extension(() => GroupMailboxRosterExtension.encode(invalid), label);
  extension(
    () =>
      GroupMailboxRosterExtension.decode(
        new Uint8Array(GroupMailboxRosterExtension.MAX_BYTES + 1).fill(0x20),
      ),
    'decode oversized',
  );
  extension(() => GroupMailboxRosterExtension.read([]), 'read none');
  extension(() => GroupMailboxRosterExtension.read([entry, entry]), 'read two');
  extension(
    () =>
      GroupMailboxRosterExtension.read([
        { extensionData, extensionType: MlsRosterFrontier.EXTENSION_TYPE },
      ]),
    'read another type',
  );

  return checked;
}
