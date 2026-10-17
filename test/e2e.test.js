// Runs real clients (the same code the browser uses) against a real relay server.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from '../server/server.js';
import { OrbiClient, KeyChangedError } from '../public/js/client.js';

let server;
let url;
const clients = [];

before(async () => {
  server = await createServer({ port: 0, host: '127.0.0.1', log: () => {} });
  url = `ws://127.0.0.1:${server.port}/ws`;
});

after(async () => {
  for (const c of clients) c.close();
  await server.close();
});

function memoryStore() {
  const m = new Map();
  return { get: async (k) => m.get(k), set: async (k, v) => void m.set(k, v), del: async (k) => void m.delete(k), raw: m };
}

async function newClient(username, store = memoryStore()) {
  const c = new OrbiClient({ url, store });
  if (!(await c.loadIdentity())) await c.createIdentity(username);
  await c.connect();
  clients.push(c);
  return c;
}

/** Resolves once `predicate()` is true, re-checking on every event of the given types. */
function until(client, types, predicate, ms = 3000) {
  return new Promise((resolve, reject) => {
    const check = () => {
      if (predicate()) {
        cleanup();
        resolve();
      }
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`timed out waiting on ${types}`));
    }, ms);
    const cleanup = () => {
      clearTimeout(timer);
      for (const t of types) client.removeEventListener(t, check);
    };
    for (const t of types) client.addEventListener(t, check);
    check();
  });
}

const texts = (c, gid) => (c.groups.get(gid)?.messages ?? []).map((m) => m.text);

test('group lifecycle: create, chat, add, remove, leave with key rotation', async () => {
  const alice = await newClient('alice');
  const bob = await newClient('bob');
  const carol = await newClient('carol');
  const dave = await newClient('dave');

  const g = await alice.createGroup('Launch team', ['bob', 'carol']);
  assert.equal(g.epoch, 1);
  await until(bob, ['groups'], () => bob.groups.get(g.id)?.keys.has(1));

  await bob.send(g.id, 'hi all');
  await until(alice, ['message'], () => texts(alice, g.id).includes('hi all'));
  await until(carol, ['message'], () => texts(carol, g.id).includes('hi all'));

  // The server only ever stores ciphertext.
  const stored = JSON.stringify(server.store.messages.get(g.id));
  assert.ok(!stored.includes('hi all'));

  // Adding dave rotates the key; dave cannot read anything from before he joined.
  await alice.addMembers(g.id, ['dave']);
  await until(dave, ['groups'], () => dave.groups.get(g.id)?.keys.has(2));
  assert.equal(dave.groups.get(g.id).keys.has(1), false);
  await dave.loadHistory(g.id);
  assert.deepEqual(texts(dave, g.id), []);

  // Removing carol: she is cut off and gets no key for the new epoch.
  await alice.removeMember(g.id, 'carol');
  await until(carol, ['groups'], () => !carol.groups.has(g.id));
  await until(bob, ['groups'], () => bob.groups.get(g.id)?.epoch === 3);
  await bob.send(g.id, 'carol is gone');
  await until(dave, ['message'], () => texts(dave, g.id).includes('carol is gone'));
  const epoch3 = server.store.groups.get(g.id).envelopes.get(3);
  assert.deepEqual(Object.keys(epoch3).sort(), ['alice', 'bob', 'dave']);

  // Bob leaves: the owner's client notices and rotates automatically.
  await bob.leave(g.id);
  await until(alice, ['groups'], () => alice.groups.get(g.id)?.epoch === 4);
  assert.deepEqual(alice.groups.get(g.id).latest.members, ['alice', 'dave']);
  await until(dave, ['groups'], () => dave.groups.get(g.id)?.keys.has(4));
  await dave.send(g.id, 'just us');
  await until(alice, ['message'], () => texts(alice, g.id).includes('just us'));
});

test('server rejects stale epochs, non-owner changes and spoofed senders', async () => {
  const erin = await newClient('erin');
  const frank = await newClient('frank');
  const g = await erin.createGroup('Ops', ['frank']);
  await until(frank, ['groups'], () => frank.groups.get(g.id)?.keys.has(1));

  await assert.rejects(frank.addMembers(g.id, ['alice']), /owner/);

  await erin.rotateKey(g.id);
  await until(frank, ['groups'], () => frank.groups.get(g.id)?.epoch === 2);

  // Pretend frank's client missed the rotation: a message on the old epoch is refused.
  const fg = frank.groups.get(g.id);
  fg.epoch = 1;
  await assert.rejects(frank.send(g.id, 'old key'), /stale epoch/);
  fg.epoch = 2;

  // Frank can't send as erin: the server checks the signature against the authenticated user.
  const { encryptMessage } = await import('../public/js/crypto.js');
  const forged = await encryptMessage({
    groupKey: fg.keys.get(2), groupId: g.id, epoch: 2, sender: 'erin', signPriv: frank.identity.signPriv, text: 'x',
  });
  await assert.rejects(frank.request('send', { msg: forged }), /sender mismatch/);
});

test('usernames are bound to their keys', async () => {
  await newClient('grace');
  const impostor = new OrbiClient({ url, store: memoryStore() });
  await impostor.createIdentity('grace');
  await assert.rejects(impostor.connect(), /already taken/);
});

test('identity persists across reconnects and group keys are cached locally', async () => {
  const store = memoryStore();
  const heidi = await newClient('heidi', store);
  const ivan = await newClient('ivan');
  const g = await ivan.createGroup('Pair', ['heidi']);
  await until(heidi, ['groups'], () => heidi.groups.get(g.id)?.keys.has(1));
  await ivan.send(g.id, 'remember me');
  heidi.close();

  const again = await newClient('heidi', store);
  assert.ok(again.groups.has(g.id));
  await again.loadHistory(g.id);
  assert.deepEqual(texts(again, g.id), ['remember me']);
  assert.ok(store.raw.has(`gk:${g.id}:1`));
});

test('a swapped contact key is detected before wrapping a group key', async () => {
  const judy = await newClient('judy');
  await newClient('mallory');
  await judy.fingerprintOf('mallory'); // pins mallory's real key
  // Simulate a server that later hands out a different key for mallory.
  const real = server.store.users.get('mallory');
  const fake = (await import('../public/js/crypto.js')).generateIdentity;
  const other = await fake();
  server.store.users.set('mallory', { ...real, signPub: other.signPubB64, dhPub: other.dhPubB64 });
  try {
    await assert.rejects(judy.createGroup('Trap', ['mallory']), KeyChangedError);
  } finally {
    server.store.users.set('mallory', real);
  }
});
