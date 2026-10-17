import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as C from '../public/js/crypto.js';

const GROUP = 'AAAAAAAAAAAAAAAAAAAAAA';

async function wrapFor(owner, recipient, name, keyBytes = C.newGroupKeyBytes(), epoch = 1) {
  const envelope = await C.wrapGroupKey({
    keyBytes, groupId: GROUP, epoch, sender: 'owner', recipient: name,
    recipientDhPubB64: recipient.dhPubB64, senderSignPriv: owner.signPriv,
  });
  return { envelope, keyBytes };
}

function unwrapAs(owner, me, name, envelope, overrides = {}) {
  return C.unwrapGroupKey({
    envelope, groupId: GROUP, epoch: 1, recipient: name, sender: 'owner',
    myDhPriv: me.dhPriv, myDhPubB64: me.dhPubB64, senderSignPub: owner.signPub, ...overrides,
  });
}

test('base64url round trip', () => {
  for (const n of [0, 1, 2, 3, 31, 32, 65]) {
    const bytes = C.randomBytes(n);
    assert.deepEqual(C.fromB64(C.toB64(bytes)), bytes);
  }
  assert.throws(() => C.fromB64('not base64!'));
});

test('canonical JSON is key-order independent', () => {
  assert.equal(C.canonical({ b: 1, a: [2, { d: 3, c: 4 }] }), C.canonical({ a: [2, { c: 4, d: 3 }], b: 1 }));
});

test('private identity keys are not extractable', async () => {
  const id = await C.generateIdentity();
  assert.equal(id.signPriv.extractable, false);
  assert.equal(id.dhPriv.extractable, false);
  await assert.rejects(globalThis.crypto.subtle.exportKey('pkcs8', id.signPriv));
});

test('fingerprints are stable and distinguish identities', async () => {
  const a = await C.generateIdentity();
  const b = await C.generateIdentity();
  const fa = await C.fingerprint(a.signPubB64, a.dhPubB64);
  assert.match(fa, /^(\d{5} ){11}\d{5}$/);
  assert.equal(fa, await C.fingerprint(a.signPubB64, a.dhPubB64));
  assert.notEqual(fa, await C.fingerprint(b.signPubB64, b.dhPubB64));
});

test('group key wraps to the intended member only', async () => {
  const owner = await C.generateIdentity();
  const alice = await C.generateIdentity();
  const eve = await C.generateIdentity();
  const { envelope } = await wrapFor(owner, alice, 'alice');

  const key = await unwrapAs(owner, alice, 'alice', envelope);
  assert.equal(key.extractable, false);

  // Eve cannot unwrap Alice's envelope even if she claims to be Alice.
  await assert.rejects(unwrapAs(owner, eve, 'alice', envelope));
});

test('unwrap rejects tampered or re-targeted envelopes', async () => {
  const owner = await C.generateIdentity();
  const alice = await C.generateIdentity();
  const { envelope } = await wrapFor(owner, alice, 'alice');

  await assert.rejects(unwrapAs(owner, alice, 'alice', { ...envelope, epoch: 2 }, { epoch: 2 }), /signature/);
  const flipped = C.fromB64(envelope.ct);
  flipped[0] ^= 1;
  await assert.rejects(unwrapAs(owner, alice, 'alice', { ...envelope, ct: C.toB64(flipped) }), /signature/);
  await assert.rejects(unwrapAs(owner, alice, 'alice', envelope, { epoch: 3 }), /does not match/);
});

test('unwrap rejects an envelope forged by someone other than the owner', async () => {
  const owner = await C.generateIdentity();
  const server = await C.generateIdentity();
  const alice = await C.generateIdentity();
  // A malicious server can encrypt to Alice's public key, but cannot sign as the owner.
  const { envelope } = await wrapFor(server, alice, 'alice');
  await assert.rejects(unwrapAs(owner, alice, 'alice', envelope), /signature/);
});

test('messages encrypt, verify and decrypt; tampering is detected', async () => {
  const owner = await C.generateIdentity();
  const alice = await C.generateIdentity();
  const mallory = await C.generateIdentity();
  const { envelope, keyBytes } = await wrapFor(owner, alice, 'alice');
  const senderKey = await C.importGroupKey(keyBytes);
  const aliceKey = await unwrapAs(owner, alice, 'alice', envelope);

  const msg = await C.encryptMessage({
    groupKey: senderKey, groupId: GROUP, epoch: 1, sender: 'owner', signPriv: owner.signPriv, text: 'hello ✨ group',
  });
  assert.ok(!JSON.stringify(msg).includes('hello'));
  assert.equal(await C.verifyMessage(msg, owner.signPub), true);
  assert.equal(await C.verifyMessage({ ...msg, receivedAt: 1 }, owner.signPub), true);
  assert.equal(await C.decryptMessage(msg, aliceKey), 'hello ✨ group');

  // Another member re-attributing the message to themselves.
  assert.equal(await C.verifyMessage({ ...msg, sender: 'mallory' }, mallory.signPub), false);
  // Header changes break the AEAD tag even without checking signatures.
  await assert.rejects(C.decryptMessage({ ...msg, sender: 'mallory' }, aliceKey));
  await assert.rejects(C.decryptMessage({ ...msg, epoch: 2 }, aliceKey));
  // A key from another epoch cannot decrypt.
  await assert.rejects(C.decryptMessage(msg, await C.importGroupKey(C.newGroupKeyBytes())));
});
