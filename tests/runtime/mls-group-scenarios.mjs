// MlsGroup scenarios shared by the Node and Chromium runs of mls-group.cjs.
// `run` takes the library bundle, the root KeyPair and the ts-mls codecs the
// tampering scenarios need, and returns the names of the scenarios it ran.

const text = new TextEncoder();
const read = (bytes) => new TextDecoder().decode(bytes);
const DEVICES = ['d1', 'd2', 'd3', 'd4', 'd9'];

const fail = (label) => {
  throw new Error('FAIL ' + label);
};
const ok = (value, label) => {
  if (!value) fail(label);
};
const comparable = (value) =>
  JSON.stringify(value, (_key, item) =>
    typeof item === 'bigint'
      ? item.toString() + 'n'
      : item instanceof Uint8Array
        ? Array.from(item)
        : item,
  );
const same = (actual, expected, label) =>
  ok(comparable(actual) === comparable(expected), label);
const rejects = async (promise, label) => {
  try {
    await promise;
  } catch (error) {
    ok(error.name === 'InvalidMlsGroupError', label + ': ' + error.name);
    ok(error.message === 'Invalid MLS group operation', label + ': message');
    return;
  }
  fail(label + ': resolved');
};

/** Every order the items can arrive in. */
const ordersOf = (items) =>
  items.length <= 1
    ? [items]
    : items.flatMap((item, index) =>
        ordersOf(items.filter((_, other) => other !== index)).map((rest) => [
          item,
          ...rest,
        ]),
      );

/**
 * A roster history: alice kicks carol, while concurrent operations b1, b2
 * and b3 descend from before the kick.
 */
const parentsOf = { b1: ['base'], b2: ['b1'], b3: ['b2'], base: [], kick: ['base'] };
/** A digest-shaped stand-in for the operation `name`. */
const op = (name) => name.padEnd(42, '-') + 'A';
const closureOf = (frontier) => {
  const seen = new Set();
  const pending = frontier.map((digest) => digest.replace(/-*A$/, ''));

  for (let name = pending.pop(); name !== undefined; name = pending.pop()) {
    if (!seen.has(name)) pending.push(...parentsOf[name]);
    seen.add(name);
  }

  return seen;
};

export async function run({ mls, KeyPair, tsMls }) {
  const {
    MlsGroup,
    MlsKeyPackage,
    MlsLeafCredential,
    MlsLeafSigner,
    MlsRosterFrontier,
  } = mls;
  const cast = {};
  const ran = [];
  let members;
  let allows;
  let latest;
  let reach;
  let withheld;
  let priority;
  let commitCounter = 0;
  const policy = {
    admits: (identityId) => members.has(identityId),
    allows: (change, order) => allows(change, order),
    frontier: () => latest,
    priority: (change) => priority(change),
    reach: (frontier) => reach(frontier),
    withheld: (committer, frontier) => withheld(committer, frontier),
  };

  for (const name of ['alice', 'bob', 'carol', 'dave', 'mallory']) {
    const keyPair = await KeyPair.generate();
    const devices = {};

    for (const device of DEVICES) devices[device] = await KeyPair.generate();
    const owner = (device = 'd1') => ({
      deviceCredential: devices[device].toPrimitives().publicKey,
      identityId: keyPair.toPrimitives().publicKey.split('\n')[1],
    });

    cast[name] = {
      deviceCredential: (device = 'd1') => owner(device).deviceCredential,
      deviceKeyPair: (device) => devices[device],
      id: owner().identityId,
      keyPair,
      owner,
      signer: (device = 'd1') =>
        new MlsLeafSigner(owner(device), keyPair, devices[device]),
    };
  }

  const idOf = (name) => cast[name].id;
  const idsOf = (...names) => names.map(idOf).sort();
  const nextId = () => 'c' + String(++commitCounter).padStart(4, '0');
  const device = (name, deviceName = 'd1') =>
    MlsKeyPackage.generate(cast[name].signer(deviceName));
  /** Only alice adds or removes; anyone may rotate their own leaf. */
  const aliceManages = ({ added, committer, removed }) =>
    committer === idOf('alice') || (added.length === 0 && removed.length === 0);
  /** Carol commits nothing once the revision holds her kick. */
  const carolKicked = ({ committer }, { frontier }) =>
    committer !== idOf('carol') || !closureOf(frontier).has('kick');
  const recordOf = (output, id) => ({
    bytes: output.commit,
    epoch: output.epoch,
    id,
  });

  const admit = async (admin, newcomers, others) => {
    const output = await admin.add(newcomers.map((key) => key.publicBytes));
    const id = nextId();
    admin.confirm(id);
    for (const other of others) await other.applyCommit(recordOf(output, id));
    const groups = await Promise.all(
      newcomers.map((key) =>
        MlsGroup.join(admin.groupId, key, output.welcome, policy),
      ),
    );

    return { groups, output };
  };

  const setup = async (names) => {
    const seats = {};
    const [first, ...rest] = names;
    const firstKey = await device(first);
    seats[first] = {
      group: await MlsGroup.create('community-1', firstKey, policy),
      key: firstKey,
    };
    const keys = await Promise.all(rest.map((name) => device(name)));
    const { groups } = await admit(seats[first].group, keys, []);
    rest.forEach((name, index) => {
      seats[name] = { group: groups[index], key: keys[index] };
    });

    return seats;
  };

  /** Commits a leaf update of `committer` that every one of `others` applies. */
  const rotate = async (committer, others) => {
    const record = recordOf(await committer.update(), nextId());
    committer.confirm(record.id);
    for (const other of others) await other.applyCommit(record);

    return record;
  };

  /** What someone who copied a member's stored group state holds. */
  const copyOf = ({ group, key }) =>
    MlsGroup.restore(
      group.groupId,
      key.owner,
      policy,
      group.serialize(),
      group.frontier,
    );

  /**
   * A member's stored group state in which the leaf of `name` shows the
   * credential `credentialFor` makes, as a tampered store would hold it.
   */
  const withCredential = ({ group, key }, name, credentialFor) => {
    const [state] = tsMls.decodeGroupState(group.serialize(), 0);
    const leaves = state.ratchetTree.flatMap((node) =>
      node?.nodeType === 'leaf' ? [node.leaf] : [],
    );
    const ratchetTree = state.ratchetTree.map((node) =>
      node?.nodeType === 'leaf' &&
      MlsLeafCredential.ownerOf(node.leaf.credential.identity).identityId ===
        idOf(name)
        ? {
            ...node,
            leaf: { ...node.leaf, credential: credentialFor(node.leaf, leaves) },
          }
        : node,
    );

    return MlsGroup.restore(
      group.groupId,
      key.owner,
      policy,
      tsMls.encodeGroupState({ ...state, ratchetTree }),
      group.frontier,
    );
  };

  const signatureKeyOf = (key) =>
    tsMls.decodeMlsMessage(key.publicBytes, 0)[0].keyPackage.leafNode
      .signaturePublicKey;

  /**
   * The state of a member whose modified client runs ts-mls without the
   * library's rules, as it would build hostile messages.
   */
  const rawStateOf = (group) => ({
    ...tsMls.decodeGroupState(group.serialize(), 0)[0],
    clientConfig: {
      authService: tsMls.defaultAuthenticationService,
      keyPackageEqualityConfig: tsMls.defaultKeyPackageEqualityConfig,
      keyRetentionConfig: tsMls.defaultKeyRetentionConfig,
      lifetimeConfig: tsMls.defaultLifetimeConfig,
      paddingConfig: tsMls.defaultPaddingConfig,
    },
  });
  const rawSuite = () =>
    tsMls.getCiphersuiteImpl(
      tsMls.getCiphersuiteFromName('MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519'),
    );
  /** A commit such a client of `group`'s member makes with `proposals`. */
  const rawCommit = async (group, proposals) => {
    const { commit } = await tsMls.createCommit(
      { cipherSuite: await rawSuite(), state: rawStateOf(group) },
      {
        authenticatedData: MlsRosterFrontier.encode(group.frontier),
        extraProposals: proposals,
        ratchetTreeExtension: true,
      },
    );

    return { bytes: tsMls.encodeMlsMessage(commit), epoch: group.epoch, id: nextId() };
  };

  const scenarios = {
    'delivers a message to every member of a multi-user group': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const sealed = await alice.group.encrypt(text.encode('hello everyone'));

      same(read(await bob.group.decrypt(sealed)), 'hello everyone', 'bob');
      same(read(await carol.group.decrypt(sealed)), 'hello everyone', 'carol');
      same(alice.group.identities().sort(), idsOf('alice', 'bob', 'carol'), 'ids');
      same(MlsGroup.groupIdOf(sealed), 'community-1', 'group id');
      same(MlsGroup.epochOf(sealed), alice.group.epoch, 'epoch');
      same(MlsGroup.groupIdOf(text.encode('x')), undefined, 'no group id');
      same(await bob.group.authenticate(sealed), cast.alice.owner(), 'sender');
    },

    'names the verified sender of an opened message': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const sealed = await bob.group.encrypt(text.encode('from bob'));
      const opened = await alice.group.open(sealed);

      same(read(opened.plaintext), 'from bob', 'plaintext');
      same(opened.sender, cast.bob.owner(), 'sender');
    },

    'lets a second device of the same identity join and read': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const phone = await device('bob', 'd2');
      const { groups } = await admit(alice.group, [phone], [bob.group]);
      const sealed = await alice.group.encrypt(text.encode('to both devices'));

      same(read(await groups[0].decrypt(sealed)), 'to both devices', 'phone');
      same(read(await bob.group.decrypt(sealed)), 'to both devices', 'bob');
      same(alice.group.identities().sort(), idsOf('alice', 'bob'), 'ids');
      same(alice.group.leaves().length, 3, 'leaves');
      same(groups[0].welcomer, cast.alice.owner(), 'welcomer');
    },

    'exposes the signature public key of every leaf for audit': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const leaves = alice.group.leaves();

      same(leaves.map(({ owner }) => owner.identityId), [idOf('alice'), idOf('bob')], 'owners');
      same(leaves[0].signaturePublicKey, signatureKeyOf(alice.key), 'alice key');
      same(leaves[1].signaturePublicKey, signatureKeyOf(bob.key), 'bob key');
      same(MlsKeyPackage.ownerOf(bob.key.publicBytes), cast.bob.owner(), 'owner');
      same(
        MlsKeyPackage.restore(bob.key.publicBytes, bob.key.privatePackage).owner,
        cast.bob.owner(),
        'restored owner',
      );
    },

    'stops a removed member from decrypting what is sent afterwards': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const before = await alice.group.encrypt(text.encode('before'));
      same(read(await carol.group.decrypt(before)), 'before', 'before');

      const removal = await alice.group.removeIdentities([idOf('carol')]);
      const record = recordOf(removal, nextId());
      alice.group.confirm(record.id);
      await bob.group.applyCommit(record);
      const carolOutcome = await carol.group.applyCommit(record);
      const after = await alice.group.encrypt(text.encode('after'));

      same(carolOutcome.kind, 'removed', 'outcome');
      ok(carol.group.isRemoved, 'is removed');
      same(read(await bob.group.decrypt(after)), 'after', 'bob');
      await rejects(carol.group.decrypt(after), 'carol decrypts');
      await rejects(carol.group.encrypt(text.encode('x')), 'carol encrypts');
      await rejects(carol.group.callMediaKey('call-1'), 'carol exports');
      await rejects(carol.group.groupMailboxGenerationSecret(), 'carol generation');
      await rejects(carol.group.update(), 'carol commits');
      same(await carol.group.applyCommit(record), { kind: 'removed' }, 'again');
      ok(!alice.group.identities().includes(idOf('carol')), 'gone');
      ok(
        MlsGroup.restore('community-1', carol.key.owner, policy, carol.group.serialize(), []).isRemoved,
        'restored removed',
      );
    },

    // RFC 9420 §12.4.2: the UpdatePath of a commit carrying a GroupContext
    // extensions proposal encrypts to the new GroupContext.
    'lets another member apply a commit that changes the context and removes a member at once': async () => {
      const extensionType = 0xf4f0;
      const keyOf = (name) =>
        MlsKeyPackage.generate(cast[name].signer('d1'), [extensionType]);
      const aliceKey = await keyOf('alice');
      const alice = await MlsGroup.create('community-1', aliceKey, policy);
      const {
        groups: [bob, carol],
      } = await admit(alice, [await keyOf('bob'), await keyOf('carol')], []);
      const context = [{ extensionData: text.encode('v2'), extensionType }];

      ok(alice.supports(extensionType), 'supports');
      const change = await alice.changeContext(context, [idOf('carol')]);
      const record = recordOf(change, nextId());
      alice.confirm(record.id);
      same((await bob.applyCommit(record)).kind, 'applied', 'bob applies');
      const after = await alice.encrypt(text.encode('after'));

      same(bob.context(), context, 'context');
      same(bob.changes().at(-1).proposedContext, context, 'proposed context');
      same(bob.identities().sort(), idsOf('alice', 'bob'), 'ids');
      same(read(await bob.decrypt(after)), 'after', 'decrypts');
      same((await carol.applyCommit(record)).kind, 'removed', 'carol');
    },

    'carries a group mailbox roster through a context change every member applies': async () => {
      const { GroupMailboxRosterExtension } = mls;
      const keyOf = (name) =>
        MlsKeyPackage.generate(cast[name].signer('d1'), [
          GroupMailboxRosterExtension.EXTENSION_TYPE,
        ]);
      const roster = (memberIds) => [
        {
          extensionData: GroupMailboxRosterExtension.encode({
            adminIds: [],
            conversationId: 'group:' + 'A'.repeat(43),
            creatorId: idOf('alice'),
            memberIds,
            name: 'Team',
            version: 1,
          }),
          extensionType: GroupMailboxRosterExtension.EXTENSION_TYPE,
        },
      ];
      const alice = await MlsGroup.create(
        'group-1',
        await keyOf('alice'),
        policy,
        roster(idsOf('alice', 'bob', 'carol')),
      );
      const {
        groups: [bob, carol],
      } = await admit(alice, [await keyOf('bob'), await keyOf('carol')], []);
      const change = await alice.changeContext(roster(idsOf('alice', 'bob')));
      const record = recordOf(change, nextId());
      alice.confirm(record.id);

      for (const member of [bob, carol]) {
        same((await member.applyCommit(record)).kind, 'applied', 'applies');
        same(
          GroupMailboxRosterExtension.read(member.context()).memberIds,
          idsOf('alice', 'bob'),
          'roster',
        );
      }
      const sealed = await alice.encrypt(text.encode('renamed'));
      same(read(await carol.decrypt(sealed)), 'renamed', 'decrypts');
    },

    'removes every device of an identity at once': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const phone = await device('bob', 'd2');
      const { groups } = await admit(alice.group, [phone], [bob.group]);
      const record = recordOf(
        await alice.group.removeIdentities([idOf('bob')]),
        nextId(),
      );
      alice.group.confirm(record.id);

      same((await bob.group.applyCommit(record)).kind, 'removed', 'bob');
      same((await groups[0].applyCommit(record)).kind, 'removed', 'phone');
      same(alice.group.leaves().length, 1, 'leaves');
    },

    'removes only the named devices of an identity': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const phone = await device('bob', 'd2');
      const { groups } = await admit(alice.group, [phone], [bob.group]);
      const record = recordOf(
        await bob.group.removeDevices(idOf('bob'), [
          cast.bob.deviceCredential('d2'),
        ]),
        nextId(),
      );
      bob.group.confirm(record.id);
      await alice.group.applyCommit(record);
      const after = await alice.group.encrypt(text.encode('after'));

      same((await groups[0].applyCommit(record)).kind, 'removed', 'phone');
      same(read(await bob.group.decrypt(after)), 'after', 'bob');
      same(
        alice.group.leaves().map(({ owner }) => owner.deviceCredential),
        [cast.alice.deviceCredential('d1'), cast.bob.deviceCredential('d1')],
        'devices',
      );
    },

    'commits nothing when no named device holds a leaf': async () => {
      const { alice } = await setup(['alice', 'bob']);

      same(
        await alice.group.removeDevices(idOf('bob'), [cast.bob.deviceCredential('d2')]),
        undefined,
        'devices',
      );
      same(await alice.group.removeIdentities([idOf('dave')]), undefined, 'identities');
    },

    'does not give a member of one group the secret of another group': async () => {
      const community = await setup(['alice', 'bob', 'carol']);
      const channel = await MlsGroup.create(
        'community-1:private',
        await device('alice', 'd3'),
        policy,
      );
      await admit(channel, [await device('bob', 'd3')], []);
      const communitySecret = await community.carol.group.callMediaKey('call-1');
      const channelSecret = await channel.callMediaKey('call-1');
      const sealedInChannel = await channel.encrypt(text.encode('restricted'));

      ok(comparable(communitySecret) !== comparable(channelSecret), 'distinct');
      await rejects(community.carol.group.decrypt(sealedInChannel), 'decrypt');
    },

    'derives different secrets per purpose, equal across members of an epoch': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const aliceMedia = comparable(await alice.group.callMediaKey('call-1'));
      const bobMedia = comparable(await bob.group.callMediaKey('call-1'));
      const otherCall = comparable(await alice.group.callMediaKey('call-2'));
      const generation = comparable(await alice.group.groupMailboxGenerationSecret());

      same(aliceMedia, bobMedia, 'equal');
      same(comparable(await bob.group.groupMailboxGenerationSecret()), generation, 'generation');
      ok(aliceMedia !== otherCall, 'context');
      ok(aliceMedia !== generation, 'purpose');
      same((await alice.group.callMediaKey('c'.repeat(256))).length, 32, 'longest');
      await rejects(alice.group.callMediaKey(''), 'empty call');
      await rejects(alice.group.callMediaKey('c'.repeat(257)), 'long call');
      await rejects(alice.group.callMediaKey('é'.repeat(129)), 'long utf8 call');
      await rejects(alice.group.callMediaKey('\uD800'), 'lone surrogate');
      await rejects(alice.group.callMediaKey(7), 'not text');
    },

    'changes the exported secret when the epoch changes': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const first = comparable(await alice.group.callMediaKey('call-1'));
      const generation = comparable(await alice.group.groupMailboxGenerationSecret());

      await rotate(alice.group, [bob.group]);
      const second = comparable(await alice.group.callMediaKey('call-1'));

      ok(first !== second, 'changed');
      ok(generation !== comparable(await alice.group.groupMailboxGenerationSecret()), 'generation');
      same(comparable(await bob.group.callMediaKey('call-1')), second, 'shared');
    },

    'applies a repeated commit only once and reports a missing one as a gap': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const first = await alice.group.update();
      alice.group.confirm('c-first');
      const second = await alice.group.update();
      alice.group.confirm('c-second');

      const gap = await bob.group.applyCommit(recordOf(second, 'c-second'));
      const record = recordOf(first, 'c-first');
      const applied = await bob.group.applyCommit(record);
      const duplicate = await bob.group.applyCommit(record);
      const caughtUp = await bob.group.applyCommit(recordOf(second, 'c-second'));

      same(gap, { got: second.epoch, have: first.epoch, kind: 'gap' }, 'gap');
      same(applied.kind, 'applied', 'applied');
      same(duplicate, { kind: 'ignored', reason: 'duplicate' }, 'duplicate');
      same(caughtUp.kind, 'applied', 'caught up');
      same(bob.group.epoch, alice.group.epoch, 'epoch');
      same(MlsGroup.frontierOf(second.commit), [], 'frontier of commit');
      same(MlsGroup.frontierOf(text.encode('x')), undefined, 'not a commit');
      same(bob.group.changes().length, 2, 'changes');
      same(bob.group.committedIdentities(), [idOf('alice')], 'committed');
    },

    'reports a commit for an epoch it never held as stale': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const record = await rotate(alice.group, [bob.group]);

      await rotate(alice.group, [bob.group]);
      const late = MlsGroup.restore(
        'community-1',
        bob.key.owner,
        policy,
        bob.group.serialize(),
        bob.group.frontier,
      );

      same(await late.applyCommit(record), { kind: 'ignored', reason: 'stale' }, 'stale');
      await rejects(late.applyCommit({ ...record, epoch: late.epoch }), 'wrong epoch');
    },

    'converges on the lowest commit id when two members commit the same epoch': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const aliceRecord = recordOf(
        await alice.group.removeIdentities([idOf('carol')]),
        'b-alice',
      );
      const bobRecord = recordOf(await bob.group.update(), 'a-bob');

      alice.group.confirm(aliceRecord.id);
      bob.group.confirm(bobRecord.id);
      const aliceSees = await alice.group.applyCommit(bobRecord);
      const bobSees = await bob.group.applyCommit(aliceRecord);
      const carolFirst = await carol.group.applyCommit(aliceRecord);
      const carolThen = await carol.group.applyCommit(bobRecord);

      same(aliceSees.kind, 'replaced', 'alice replaced');
      same(aliceSees.discardedCommitId, 'b-alice', 'discarded');
      same(bobSees, { kind: 'ignored', reason: 'lost-race' }, 'bob');
      same(carolFirst.kind, 'removed', 'carol first');
      same(carolThen.kind, 'removed', 'carol then');
      same(alice.group.epoch, bob.group.epoch, 'epoch');
      ok(alice.group.identities().includes(idOf('carol')), 'carol stays');
      const sealed = await alice.group.encrypt(text.encode('converged'));
      same(read(await bob.group.decrypt(sealed)), 'converged', 'decrypts');
    },

    'converges on one rival, never the kicked one, in every arrival order': async () => {
      const { alice, bob, carol, dave } = await setup(['alice', 'bob', 'carol', 'dave']);
      const before = dave.group.serialize();
      const commitAt = async (frontier, id, make) => {
        latest = frontier.map(op);

        return recordOf(await make(), id);
      };
      // Alice removes carol bound to the kick; bob rotates his leaf bound to
      // a concurrent branch; carol, kicked, rotates hers bound to more of
      // that branch, with the lowest id.
      const removal = await commitAt(['kick'], 'c-alice', () =>
        alice.group.removeIdentities([idOf('carol')]),
      );
      const honest = await commitAt(['b2'], 'b-bob', () => bob.group.update());
      const kicked = await commitAt(['b3'], 'a-carol', () => carol.group.update());
      bob.group.confirm(honest.id);
      allows = carolKicked;
      reach = (frontier) => closureOf(frontier).size;
      latest = [op('kick'), op('b3')];
      const sealed = await bob.group.encrypt(text.encode('bob won'));

      for (const order of ordersOf([removal, honest, kicked])) {
        const receiver = MlsGroup.restore('community-1', dave.key.owner, policy, before, []);

        for (const record of order) {
          await receiver.applyCommit(record).catch(() => undefined);
        }

        same(read(await receiver.decrypt(sealed)), 'bob won', 'order');
      }
    },

    'goes on with its sending generations when it takes again an add it stepped back from': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const add = await alice.group.add([(await device('dave')).publicBytes]);
      const record = recordOf(add, nextId());

      alice.group.confirm(record.id);
      // Carol's rival binds an operation the node has not served bob yet.
      latest = [op('kick')];
      const rival = await carol.group.update();
      latest = [];
      await bob.group.applyCommit(record);
      const first = await bob.group.encrypt(text.encode('before the witness'));

      same(read(await alice.group.decrypt(first)), 'before the witness', 'first');
      withheld = (_committer, frontier) => frontier.includes(op('kick'));
      same(
        await bob.group.applyCommit(recordOf(rival, nextId())),
        { kind: 'ignored', reason: 'withheld' },
        'withheld',
      );
      ok(bob.group.waiting, 'waiting');
      await rejects(bob.group.update(), 'commits while waiting');
      same(bob.group.epoch, record.epoch, 'stepped back');
      // The operation arrives and allows the add after all.
      withheld = () => false;
      same((await bob.group.applyCommit(record)).kind, 'applied', 'resumed');
      const second = await bob.group.encrypt(text.encode('after the operation'));

      same(read(await alice.group.decrypt(second)), 'after the operation', 'second');
    },

    'never steps back past a commit of its own': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const add = await alice.group.add([(await device('dave')).publicBytes]);
      const record = recordOf(add, nextId());

      alice.group.confirm(record.id);
      latest = [op('kick')];
      const rival = await carol.group.update();
      latest = [];
      await bob.group.applyCommit(record);
      const rotated = await bob.group.update();

      bob.group.confirm(nextId());
      withheld = (_committer, frontier) => frontier.includes(op('kick'));
      await bob.group.applyCommit(recordOf(rival, nextId()));

      same(bob.group.epoch, rotated.epoch + 1n, 'epoch');
    },

    'lets a rival the policy ranks higher win its epoch over a lower commit id': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const aliceRecord = recordOf(
        await alice.group.removeIdentities([idOf('carol')]),
        'b-alice',
      );
      const bobRecord = recordOf(await bob.group.update(), 'a-bob');
      priority = ({ removed }) => removed.length;

      alice.group.confirm(aliceRecord.id);
      bob.group.confirm(bobRecord.id);
      const aliceSees = await alice.group.applyCommit(bobRecord);
      const bobSees = await bob.group.applyCommit(aliceRecord);
      const carolFirst = await carol.group.applyCommit(bobRecord);
      const carolThen = await carol.group.applyCommit(aliceRecord);

      same(aliceSees, { kind: 'ignored', reason: 'lost-race' }, 'alice');
      same(bobSees.kind, 'replaced', 'bob replaced');
      same(bobSees.discardedCommitId, 'a-bob', 'discarded');
      same(carolFirst.kind, 'applied', 'carol first');
      same(carolThen.kind, 'removed', 'carol then');
      ok(!bob.group.identities().includes(idOf('carol')), 'carol gone');
      const sealed = await alice.group.encrypt(text.encode('converged'));
      same(read(await bob.group.decrypt(sealed)), 'converged', 'decrypts');
    },

    'lets a rival the verified roster still allows win over one it no longer allows': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const carolRecord = recordOf(await carol.group.update(), 'a-carol');
      const bobRecord = recordOf(await bob.group.update(), 'b-bob');

      await alice.group.applyCommit(carolRecord);
      allows = (change) => change.committer !== idOf('carol');
      const outcome = await alice.group.applyCommit(bobRecord);

      same(outcome.kind, 'replaced', 'replaced');
      same(outcome.discardedCommitId, 'a-carol', 'discarded');
    },

    'converges on the highest priority, then the lowest commit id, in every arrival order': async () => {
      const { alice, bob, carol, dave } = await setup(['alice', 'bob', 'carol', 'dave']);
      const before = dave.group.serialize();
      const rotation = async (seat, id) => recordOf(await seat.group.update(), id);
      // Alice and bob rank above carol, who holds the lowest id.
      const rivals = [
        await rotation(alice, 'c-alice'),
        await rotation(bob, 'b-bob'),
        await rotation(carol, 'a-carol'),
      ];
      bob.group.confirm('b-bob');
      priority = ({ committer }) => (committer === idOf('carol') ? 0 : 1);
      const sealed = await bob.group.encrypt(text.encode('bob won'));

      for (const order of ordersOf(rivals)) {
        const receiver = MlsGroup.restore('community-1', dave.key.owner, policy, before, []);

        for (const record of order) await receiver.applyCommit(record);

        same(read(await receiver.decrypt(sealed)), 'bob won', 'order');
      }
    },

    'lets a removed member rejoin with a fresh key package and read only what follows': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const old = await alice.group.encrypt(text.encode('old history'));
      const record = recordOf(
        await alice.group.removeIdentities([idOf('carol')]),
        nextId(),
      );
      alice.group.confirm(record.id);
      await bob.group.applyCommit(record);
      await carol.group.applyCommit(record);

      const { groups } = await admit(alice.group, [await device('carol', 'd2')], [bob.group]);
      const fresh = await alice.group.encrypt(text.encode('new history'));

      same(read(await groups[0].decrypt(fresh)), 'new history', 'fresh');
      await rejects(groups[0].decrypt(old), 'old');
    },

    'does not let a new member read earlier messages': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const earlier = await alice.group.encrypt(text.encode('before dave'));
      const { groups } = await admit(alice.group, [await device('dave')], [bob.group]);

      await rejects(groups[0].decrypt(earlier), 'earlier');
    },

    'refuses to add a key package whose identity is not a community member': async () => {
      const { alice } = await setup(['alice', 'bob']);

      await rejects(alice.group.add([(await device('mallory')).publicBytes]), 'add');
    },

    'refuses to join from a welcome the roster does not admit': async () => {
      const { alice } = await setup(['alice', 'bob']);
      const dave = await device('dave');
      const output = await alice.group.add([dave.publicBytes]);

      await rejects(MlsGroup.join('community-2', dave, output.welcome, policy), 'group id');
      members.delete(idOf('bob'));
      await rejects(MlsGroup.join('community-1', dave, output.welcome, policy), 'admits');
    },

    'rejects a commit that adds an identity the receiver knows is not a member': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      members.add(idOf('mallory'));
      const output = await alice.group.add([(await device('mallory')).publicBytes]);
      alice.group.confirm('c-mallory');
      members.delete(idOf('mallory'));

      await rejects(bob.group.applyCommit(recordOf(output, 'c-mallory')), 'apply');
      ok(!bob.group.identities().includes(idOf('mallory')), 'not added');
    },

    'refuses a key package whose credential names an identity that did not sign it': async () => {
      const { alice } = await setup(['alice', 'bob']);
      // Mallory's key, presenting a device as bob's.
      const forged = await MlsKeyPackage.generate(
        new MlsLeafSigner(
          cast.bob.owner('d9'),
          cast.mallory.keyPair,
          cast.bob.deviceKeyPair('d9'),
        ),
      );

      await rejects((async () => MlsKeyPackage.ownerOf(forged.publicBytes))(), 'owner');
      await rejects(alice.group.add([forged.publicBytes]), 'add');
      same(alice.group.leaves().length, 2, 'leaves');
    },

    'refuses a leaf a revoked device presents as a current device of its identity': async () => {
      const { alice } = await setup(['alice', 'bob']);
      // Bob's identity key, kept by a revoked device, cannot sign as bob's d2.
      const forged = await MlsKeyPackage.generate(
        new MlsLeafSigner(
          cast.bob.owner('d2'),
          cast.bob.keyPair,
          cast.bob.deviceKeyPair('d9'),
        ),
      );

      await rejects((async () => MlsKeyPackage.ownerOf(forged.publicBytes))(), 'owner');
      await rejects(alice.group.add([forged.publicBytes]), 'add');
    },

    'refuses to commit an add the roster does not let this member make': async () => {
      const { bob } = await setup(['alice', 'bob']);
      allows = aliceManages;

      await rejects(bob.group.add([(await device('dave')).publicBytes]), 'add');
      ok(!bob.group.identities().includes(idOf('dave')), 'not added');
    },

    'rejects a removal by a member the roster does not let remove': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      // Bob's client ignores the rule; alice and carol enforce it.
      const record = recordOf(
        await bob.group.removeIdentities([idOf('carol')]),
        'c-bob',
      );
      bob.group.confirm('c-bob');
      allows = aliceManages;

      await rejects(alice.group.applyCommit(record), 'alice');
      await rejects(carol.group.applyCommit(record), 'carol');
      ok(alice.group.identities().includes(idOf('carol')), 'carol stays');
      ok(!carol.group.isRemoved, 'carol not removed');
    },

    'rejects a commit whose committer leaf credential does not verify, whatever identity it names': async () => {
      const seats = await setup(['alice', 'bob', 'carol', 'dave']);
      const record = recordOf(
        await seats.bob.group.removeIdentities([idOf('carol')]),
        'c-bob',
      );
      seats.bob.group.confirm('c-bob');
      allows = aliceManages;
      // Dave's tree names alice on bob's leaf key: a credential alice signed
      // for her own leaf key, which does not verify for bob's.
      const dave = withCredential(seats.dave, 'bob', (_bob, leaves) =>
        leaves.find(
          ({ credential }) =>
            MlsLeafCredential.ownerOf(credential.identity).identityId === idOf('alice'),
        ).credential,
      );

      await rejects(dave.applyCommit(record), 'apply');
      ok(dave.identities().includes(idOf('carol')), 'carol stays');
    },

    'rejects a commit whose committer hands its own leaf to another identity': async () => {
      const seats = await setup(['alice', 'bob']);
      // Bob's patched client also holds mallory's keys and has her identity
      // and device sign bob's leaf key: a credential that verifies.
      const bob = withCredential(seats.bob, 'bob', ({ signaturePublicKey }) => ({
        credentialType: 'basic',
        identity: MlsLeafCredential.issue(cast.mallory.signer(), signaturePublicKey),
      }));
      const update = await bob.update();
      bob.confirm('c-swap');

      await rejects(seats.alice.group.applyCommit(recordOf(update, 'c-swap')), 'apply');
      same(seats.alice.group.identities().sort(), idsOf('alice', 'bob'), 'ids');
    },

    'still applies a leaf rotation by a member who may not change membership': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      allows = aliceManages;
      const update = await bob.group.update();
      bob.group.confirm('c-update');

      same((await alice.group.applyCommit(recordOf(update, 'c-update'))).kind, 'applied', 'applied');
    },

    'keeps a pending commit aside until it is confirmed or abandoned': async () => {
      const { alice } = await setup(['alice', 'bob']);
      const epoch = alice.group.epoch;

      ok(throws(() => alice.group.pendingState()), 'nothing pending');
      ok(throws(() => alice.group.confirm('c-none')), 'nothing to confirm');
      await alice.group.update();
      const pending = alice.group.pendingState();
      same(pending.frontier, [], 'pending frontier');
      same(
        MlsGroup.restore('community-1', alice.key.owner, policy, pending.state, []).epoch,
        epoch + 1n,
        'pending epoch',
      );
      alice.group.abandon();
      ok(throws(() => alice.group.pendingState()), 'abandoned');
      same(alice.group.epoch, epoch, 'unchanged');
    },

    'refuses to confirm a pending commit once another commit took its epoch': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      await alice.group.update();
      await rotate(bob.group, [alice.group]);

      ok(throws(() => alice.group.confirm('c-late')), 'confirm');
    },

    'refuses to confirm a commit built on a commit a rival then replaced': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const rival = recordOf(await carol.group.update(), 'a-carol');
      const first = recordOf(await alice.group.update(), 'b-alice');

      alice.group.confirm(first.id);
      await bob.group.applyCommit(first);
      const built = await bob.group.update();

      same((await bob.group.applyCommit(rival)).kind, 'replaced', 'replaced');
      same(bob.group.epoch, built.epoch, 'same epoch');
      ok(throws(() => bob.group.confirm('c-forked')), 'confirm');
      ok(throws(() => bob.group.pendingState()), 'dropped');
      same(bob.group.epoch, built.epoch, 'kept');
    },

    'refuses a stored state of another group or garbage': async () => {
      const { alice } = await setup(['alice', 'bob']);
      const state = alice.group.serialize();

      ok(throws(() => MlsGroup.restore('community-2', alice.key.owner, policy, state, [])), 'group');
      ok(throws(() => MlsGroup.restore('community-1', alice.key.owner, policy, new Uint8Array([1]), [])), 'garbage');
      ok(throws(() => MlsGroup.restore('community-1', alice.key.owner, policy, new Uint8Array(), [])), 'empty');
      const corrupt = state.slice();
      // The group id's length prefix now claims 8 bytes, which ts-mls refuses.
      corrupt[4] = 0xff;
      ok(throws(() => MlsGroup.restore('community-1', alice.key.owner, policy, corrupt, [])), 'corrupt');
    },

    'rejects messages it cannot read as the kind asked for': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const record = recordOf(await bob.group.update(), 'c-bob');

      await rejects(alice.group.decrypt(record.bytes), 'commit as message');
      await rejects(alice.group.decrypt(text.encode('x')), 'garbage');
      await rejects(alice.group.applyCommit({ ...record, bytes: text.encode('x') }), 'garbage commit');
      ok(throws(() => MlsGroup.epochOf(text.encode('x'))), 'epoch of garbage');
      const sealed = await bob.group.encrypt(text.encode('x'));
      await rejects(alice.group.applyCommit({ ...record, bytes: sealed }), 'message as commit');
      await rejects(alice.group.authenticate(sealed.slice(0, sealed.length - 40)), 'truncated');
    },

    'rejects a standalone proposal': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const { message } = await tsMls.createProposal(
        rawStateOf(carol.group),
        false,
        { proposalType: 'remove', remove: { removed: 0 } },
        await rawSuite(),
        MlsRosterFrontier.encode(carol.group.frontier),
      );
      const record = { bytes: tsMls.encodeMlsMessage(message), epoch: bob.group.epoch, id: nextId() };

      await rejects(bob.group.applyCommit(record), 'proposal');
      same(bob.group.identities(), alice.group.identities(), 'roster');
    },

    'rejects a commit adding a key package whose credential does not verify': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const { publicPackage } = await tsMls.generateKeyPackage(
        { credentialType: 'basic', identity: text.encode('mallory') },
        tsMls.defaultCapabilities(),
        tsMls.defaultLifetime,
        [],
        await rawSuite(),
      );
      const add = { add: { keyPackage: publicPackage }, proposalType: 'add' };

      await rejects(bob.group.applyCommit(await rawCommit(alice.group, [add])), 'add');
    },

    'rejects a commit that reinitializes the group': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const reinit = {
        proposalType: 'reinit',
        reinit: {
          cipherSuite: 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519',
          extensions: [],
          groupId: text.encode('community-2'),
          version: 'mls10',
        },
      };

      await rejects(bob.group.applyCommit(await rawCommit(alice.group, [reinit])), 'reinit');
    },

    'refuses to commit its own removal': async () => {
      const { alice } = await setup(['alice', 'bob']);

      await rejects(
        alice.group.removeDevices(idOf('alice'), [cast.alice.deviceCredential()]),
        'own removal',
      );
      ok(alice.group.identities().includes(idOf('alice')), 'still a member');
    },

    'rejects a malformed rival for an epoch it took': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const record = await rotate(alice.group, [bob.group]);

      await rejects(
        bob.group.applyCommit({ ...record, bytes: text.encode('x'), id: 'a-rival' }),
        'malformed rival',
      );
      same(bob.group.epoch, alice.group.epoch, 'epoch');
    },

    'drops the commits after an epoch a rival wins': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const rival = recordOf(await carol.group.update(), 'a-carol');
      const first = recordOf(await alice.group.update(), 'b-alice');

      alice.group.confirm(first.id);
      await bob.group.applyCommit(first);
      await rotate(alice.group, [bob.group]);
      same(bob.group.changes().length, 2, 'taken');

      same((await bob.group.applyCommit(rival)).kind, 'replaced', 'replaced');
      same(bob.group.epoch, rival.epoch + 1n, 'epoch');
      same(bob.group.changes().length, 1, 'dropped');
    },

    'ignores a rival for an epoch past the 8 it keeps as stale': async () => {
      const { alice, bob, carol } = await setup(['alice', 'bob', 'carol']);
      const rival = recordOf(await carol.group.update(), 'a-carol');
      const first = recordOf(await alice.group.update(), 'b-alice');

      alice.group.confirm(first.id);
      await bob.group.applyCommit(first);
      for (let step = 0; step < 7; step++) await rotate(alice.group, [bob.group]);
      same((await bob.group.applyCommit(rival)).kind, 'replaced', 'inside');

      const taken = alice.group.changes().length;
      await rotate(alice.group, []);
      same(await alice.group.applyCommit(rival), { kind: 'ignored', reason: 'stale' }, 'past');
      same(alice.group.changes().length, taken + 1, 'changes kept');
    },

    'waits on a commit for its own epoch that binds withheld operations': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      latest = [op('kick')];
      const record = recordOf(await alice.group.update(), nextId());
      latest = [];
      withheld = (_committer, frontier) => frontier.includes(op('kick'));

      same(
        await bob.group.applyCommit(record),
        { kind: 'ignored', reason: 'withheld' },
        'withheld',
      );
      ok(bob.group.waiting, 'waiting');
      same(bob.group.epoch, record.epoch, 'epoch');
      withheld = () => false;
      same((await bob.group.applyCommit(record)).kind, 'applied', 'applied');
    },

    'survives serialization of the group state': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const restored = copyOf(bob);
      const sealed = await alice.group.encrypt(text.encode('after restart'));

      same(read(await restored.decrypt(sealed)), 'after restart', 'decrypts');
    },

    'deletes a message key once it is used, also from the stored state': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const sealed = await alice.group.encrypt(text.encode('read once'));
      const copiedBeforeReading = copyOf(bob);

      same(read(await bob.group.decrypt(sealed)), 'read once', 'first');
      await rejects(bob.group.decrypt(sealed), 'again');
      await rejects(copyOf(bob).decrypt(sealed), 'copy');
      await rejects(alice.group.decrypt(sealed), 'own');
      same(read(await copiedBeforeReading.decrypt(sealed)), 'read once', 'earlier copy');
    },

    'forgets epoch secrets older than the current epoch and the 8 before it': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const kept = await alice.group.encrypt(text.encode('kept'));
      const lost = await alice.group.encrypt(text.encode('lost'));

      for (let step = 0; step < 8; step++) await rotate(alice.group, [bob.group]);
      same(read(await bob.group.decrypt(kept)), 'kept', 'kept');
      await rotate(alice.group, [bob.group]);

      await rejects(bob.group.decrypt(lost), 'lost');
      await rejects(copyOf(bob).decrypt(lost), 'lost copy');
    },

    'heals a copied member state only once that member commits its own update': async () => {
      const { alice, bob } = await setup(['alice', 'bob']);
      const copy = copyOf(bob);
      const callKey = async (group) => comparable(await group.callMediaKey('call-1'));
      const signatureKeys = (group) =>
        group.leaves().map(({ signaturePublicKey }) => signaturePublicKey);

      // Another member's update does not heal it: the copy follows it.
      const aliceUpdate = await rotate(alice.group, [bob.group]);
      same((await copy.applyCommit(aliceUpdate)).kind, 'applied', 'copy follows');
      const exposed = await alice.group.encrypt(text.encode('still exposed'));
      same(read(await copy.decrypt(exposed)), 'still exposed', 'exposed');
      same(await callKey(copy), await callKey(alice.group), 'exposed key');

      // Bob's own update encrypts its path secrets to alice's keys only.
      const aliceCopy = copyOf(alice);
      const signedBefore = signatureKeys(alice.group);
      const bobUpdate = await rotate(bob.group, [alice.group]);
      same((await aliceCopy.applyCommit(bobUpdate)).kind, 'applied', 'alice copy');
      await rejects(copy.applyCommit(bobUpdate), 'healed');
      const healed = await alice.group.encrypt(text.encode('healed'));

      same(read(await bob.group.decrypt(healed)), 'healed', 'bob');
      await rejects(copy.decrypt(healed), 'copy');
      same(await callKey(aliceCopy), await callKey(alice.group), 'alice copy key');
      ok(comparable(await callKey(copy)) !== comparable(await callKey(alice.group)), 'copy key');
      // The update replaces bob's encryption key, not his signature key.
      same(signatureKeys(alice.group), signedBefore, 'signature keys');
    },
  };

  function throws(work) {
    try {
      work();
    } catch (error) {
      return error.name === 'InvalidMlsGroupError';
    }

    return false;
  }

  for (const [name, scenario] of Object.entries(scenarios)) {
    members = new Set(['alice', 'bob', 'carol', 'dave'].map(idOf));
    allows = () => true;
    latest = [];
    reach = () => 0;
    withheld = () => false;
    priority = () => 0;
    try {
      await scenario();
    } catch (error) {
      error.message = name + ': ' + error.message;
      throw error;
    }
    ran.push(name);
  }

  return ran;
}
