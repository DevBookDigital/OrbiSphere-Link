// OrbiSphere Link client core. Holds no DOM code so it can run in the browser
// and in Node tests. All encryption and verification happens here; the server
// is treated as untrusted for confidentiality and integrity.

import * as C from './crypto.js';
import { normalizeMembers, normalizeUsername, MAX_TEXT_LENGTH } from './protocol.js';

const REQUEST_TIMEOUT_MS = 15_000;

export class KeyChangedError extends Error {
  constructor(username) {
    super(`The identity key for "${username}" has changed. Do not trust it until you have re-verified their safety number.`);
    this.name = 'KeyChangedError';
    this.username = username;
  }
}

export class OrbiClient extends EventTarget {
  /**
   * @param {object} opts
   * @param {string} opts.url              WebSocket URL of the relay
   * @param {{get, set, del}} opts.store   async key/value store (IndexedDB in the browser)
   */
  constructor({ url, store, WebSocketImpl = globalThis.WebSocket }) {
    super();
    this.url = url;
    this.store = store;
    this.WS = WebSocketImpl;
    this.identity = null;
    this.ws = null;
    this.rid = 0;
    this.pending = new Map();
    this.groups = new Map();
    this.contacts = new Map();
    this.seen = new Set();
    this.rekeying = new Set();
    this.inbox = Promise.resolve();
  }

  get username() {
    return this.identity?.username;
  }

  // ------------------------------------------------------------ identity

  async loadIdentity() {
    this.identity = (await this.store.get('identity')) ?? null;
    return this.identity;
  }

  async createIdentity(username) {
    const id = await C.generateIdentity();
    this.identity = { username: normalizeUsername(username), ...id };
    await this.store.set('identity', this.identity);
    return this.identity;
  }

  myFingerprint() {
    return C.fingerprint(this.identity.signPubB64, this.identity.dhPubB64);
  }

  // ------------------------------------------------------------ transport

  connect() {
    return new Promise((resolve, reject) => {
      const ws = new this.WS(this.url);
      this.ws = ws;
      let authed = false;
      ws.onmessage = (ev) => {
        let m;
        try {
          m = JSON.parse(typeof ev.data === 'string' ? ev.data : String(ev.data));
        } catch {
          return;
        }
        if (m.t === 'res') return this.#onResponse(m);
        if (m.t === 'challenge') {
          this.#authenticate(m.nonce).then((res) => {
            authed = true;
            resolve(res);
          }, (err) => {
            reject(err);
            ws.close();
          });
          return;
        }
        // Pushes are handled strictly in order, e.g. a new epoch before its first message.
        this.inbox = this.inbox.then(() => this.#onPush(m)).catch((err) => this.#emit('error', err));
      };
      ws.onclose = () => {
        for (const p of this.pending.values()) p.reject(new Error('Connection closed'));
        this.pending.clear();
        if (!authed) reject(new Error('Could not connect to the server'));
        this.#emit('disconnected');
      };
      ws.onerror = () => {};
    });
  }

  close() {
    this.ws?.close();
  }

  request(t, payload = {}) {
    return new Promise((resolve, reject) => {
      if (!this.ws || this.ws.readyState !== 1) {
        reject(new Error('Not connected'));
        return;
      }
      const rid = ++this.rid;
      const timer = setTimeout(() => {
        this.pending.delete(rid);
        reject(new Error(`Request "${t}" timed out`));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(rid, {
        resolve: (v) => { clearTimeout(timer); resolve(v); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      });
      this.ws.send(JSON.stringify({ ...payload, t, rid }));
    });
  }

  #onResponse(m) {
    const p = this.pending.get(m.rid);
    if (!p) return;
    this.pending.delete(m.rid);
    if (m.ok) p.resolve(m.data);
    else p.reject(new Error(m.error));
  }

  async #authenticate(nonce) {
    const id = this.identity;
    const body = { purpose: 'orbisphere-auth', v: 1, nonce, username: id.username, signPub: id.signPubB64, dhPub: id.dhPubB64 };
    const res = await this.request('auth', { ...body, sig: await C.signObj(id.signPriv, body) });
    await this.sync();
    return res;
  }

  async #onPush(m) {
    if (m.t === 'group') {
      await this.#ingestGroup(m.group);
    } else if (m.t === 'msg') {
      await this.#ingestMessage(m.msg);
    } else if (m.t === 'removed') {
      this.groups.delete(m.groupId);
      this.#emit('removed', { groupId: m.groupId });
      this.#emit('groups');
    }
  }

  #emit(type, detail) {
    this.dispatchEvent(Object.assign(new Event(type), { detail }));
  }

  // ------------------------------------------------------------ contacts (trust on first use)

  async getContact(username) {
    if (username === this.username) {
      return { username, signPub: this.identity.signPubB64, dhPub: this.identity.dhPubB64, signKey: this.identity.signPub, verified: true };
    }
    if (this.contacts.has(username)) return this.contacts.get(username);
    let rec = await this.store.get(`contact:${username}`);
    if (!rec) {
      const { users } = await this.request('lookup', { usernames: [username] });
      if (!users[username]) throw new Error(`Unknown user "${username}"`);
      rec = await this.#pin(username, users[username]);
    }
    return this.#cacheContact(rec);
  }

  async #pin(username, keys) {
    const rec = { username, signPub: keys.signPub, dhPub: keys.dhPub, pinnedAt: Date.now(), verified: false };
    await this.store.set(`contact:${username}`, rec);
    return rec;
  }

  async #cacheContact(rec) {
    const contact = { ...rec, signKey: await C.importSignPub(rec.signPub) };
    this.contacts.set(rec.username, contact);
    return contact;
  }

  /**
   * Fetches current keys for everyone we are about to encrypt a group key to,
   * pinning new contacts and refusing if a pinned key has been swapped.
   */
  async #contactsForWrap(members) {
    const others = members.filter((m) => m !== this.username);
    const { users } = others.length ? await this.request('lookup', { usernames: others }) : { users: {} };
    const out = new Map([[this.username, await this.getContact(this.username)]]);
    for (const name of others) {
      const keys = users[name];
      if (!keys) throw new Error(`Unknown user "${name}"`);
      let rec = await this.store.get(`contact:${name}`);
      if (rec && (rec.signPub !== keys.signPub || rec.dhPub !== keys.dhPub)) {
        this.#emit('keychange', { username: name });
        throw new KeyChangedError(name);
      }
      rec ??= await this.#pin(name, keys);
      out.set(name, this.contacts.get(name) ?? await this.#cacheContact(rec));
    }
    return out;
  }

  async fingerprintOf(username) {
    const c = await this.getContact(username);
    return C.fingerprint(c.signPub, c.dhPub);
  }

  async setVerified(username, verified) {
    const c = await this.getContact(username);
    const rec = { username, signPub: c.signPub, dhPub: c.dhPub, pinnedAt: c.pinnedAt, verified: Boolean(verified) };
    await this.store.set(`contact:${username}`, rec);
    await this.#cacheContact(rec);
    this.#emit('groups');
  }

  // ------------------------------------------------------------ groups

  async sync() {
    const { groups } = await this.request('sync');
    const ids = new Set();
    for (const rec of groups) {
      try {
        await this.#ingestGroup(rec);
        ids.add(rec.groupId);
      } catch (err) {
        this.#emit('error', err);
      }
    }
    for (const id of this.groups.keys()) if (!ids.has(id)) this.groups.delete(id);
    this.#emit('groups');
  }

  /** Verifies the owner-signed chain of group states: epoch 1..n, same owner, every signature valid. */
  async #verifyStates(rec) {
    if (!Array.isArray(rec.states) || rec.states.length === 0) throw new Error('Group has no state');
    const owner = rec.states[0].state.owner;
    const ownerContact = await this.getContact(owner);
    const states = [];
    for (const [i, { state, stateSig }] of rec.states.entries()) {
      if (state.groupId !== rec.groupId || state.owner !== owner || state.epoch !== i + 1
          || !Array.isArray(state.members) || !state.members.includes(owner)) {
        throw new Error(`Group ${rec.groupId} has an inconsistent state history`);
      }
      if (!(await C.verifyObj(ownerContact.signKey, stateSig, state))) {
        throw new Error(`Group ${rec.groupId} epoch ${state.epoch} is not signed by its owner`);
      }
      states.push(state);
    }
    return states;
  }

  async #ingestGroup(rec) {
    const states = await this.#verifyStates(rec);
    const latest = states.at(-1);
    const g = this.groups.get(rec.groupId) ?? { id: rec.groupId, keys: new Map(), messages: [], historyLoaded: false };
    Object.assign(g, {
      states,
      latest,
      name: latest.name,
      owner: latest.owner,
      epoch: latest.epoch,
      // Server-side delivery list: may lag the signed state when someone has just left.
      serverMembers: Array.isArray(rec.members) ? rec.members : latest.members,
      needsRekey: Boolean(rec.needsRekey),
    });
    const owner = await this.getContact(g.owner);
    for (const [epochStr, envelope] of Object.entries(rec.envelopes ?? {})) {
      const epoch = Number(epochStr);
      if (g.keys.has(epoch) || !states[epoch - 1]?.members.includes(this.username)) continue;
      const cacheKey = `gk:${g.id}:${epoch}`;
      let key = await this.store.get(cacheKey);
      if (!key) {
        key = await C.unwrapGroupKey({
          envelope,
          groupId: g.id,
          epoch,
          recipient: this.username,
          sender: g.owner,
          myDhPriv: this.identity.dhPriv,
          myDhPubB64: this.identity.dhPubB64,
          senderSignPub: owner.signKey,
        });
        await this.store.set(cacheKey, key);
      }
      g.keys.set(epoch, key);
    }
    this.groups.set(g.id, g);
    this.#emit('groups');
    if (g.owner === this.username && g.needsRekey) this.#autoRekey(g.id);
    return g;
  }

  /** Signs a new group state, generates a fresh group key and wraps it to every member. */
  async #publishEpoch({ groupId, name, members, epoch }, requestType) {
    const contacts = await this.#contactsForWrap(members);
    const state = { v: 1, groupId, name, owner: this.username, members, epoch, ts: Date.now() };
    const keyBytes = C.newGroupKeyBytes();
    const envelopes = {};
    try {
      for (const m of members) {
        envelopes[m] = await C.wrapGroupKey({
          keyBytes, groupId, epoch, sender: this.username, recipient: m,
          recipientDhPubB64: contacts.get(m).dhPub, senderSignPriv: this.identity.signPriv,
        });
      }
    } finally {
      keyBytes.fill(0);
    }
    const stateSig = await C.signObj(this.identity.signPriv, state);
    const { group } = await this.request(requestType, { state, stateSig, envelopes });
    return this.#ingestGroup(group);
  }

  async createGroup(name, memberNames) {
    const cleanName = String(name).trim();
    if (!cleanName) throw new Error('Group name is required');
    const members = normalizeMembers([this.username, ...memberNames]);
    const groupId = C.toB64(C.randomBytes(16));
    return this.#publishEpoch({ groupId, name: cleanName, members, epoch: 1 }, 'createGroup');
  }

  #ownedGroup(groupId) {
    const g = this.groups.get(groupId);
    if (!g) throw new Error('Unknown group');
    if (g.owner !== this.username) throw new Error('Only the group owner can change membership');
    return g;
  }

  /** Current members minus anyone who has left since the last signed epoch. */
  #activeMembers(g) {
    return g.latest.members.filter((m) => g.serverMembers.includes(m));
  }

  async #changeMembers(groupId, members) {
    const g = this.#ownedGroup(groupId);
    return this.#publishEpoch({ groupId, name: g.name, members: normalizeMembers(members), epoch: g.epoch + 1 }, 'rekey');
  }

  async addMembers(groupId, names) {
    const g = this.#ownedGroup(groupId);
    return this.#changeMembers(groupId, [...this.#activeMembers(g), ...names]);
  }

  async removeMember(groupId, name) {
    const g = this.#ownedGroup(groupId);
    if (name === this.username) throw new Error('The owner cannot remove themselves');
    return this.#changeMembers(groupId, this.#activeMembers(g).filter((m) => m !== name));
  }

  /** Replaces the group key without changing membership (e.g. after a device is lost). */
  async rotateKey(groupId) {
    return this.#changeMembers(groupId, this.#activeMembers(this.#ownedGroup(groupId)));
  }

  async #autoRekey(groupId) {
    if (this.rekeying.has(groupId)) return;
    this.rekeying.add(groupId);
    try {
      await this.rotateKey(groupId);
    } catch (err) {
      this.#emit('error', err);
    } finally {
      this.rekeying.delete(groupId);
    }
  }

  async leave(groupId) {
    await this.request('leave', { groupId });
    this.groups.delete(groupId);
    this.#emit('groups');
  }

  // ------------------------------------------------------------ messages

  async send(groupId, text) {
    const g = this.groups.get(groupId);
    if (!g) throw new Error('Unknown group');
    if (typeof text !== 'string' || !text.trim()) throw new Error('Message is empty');
    if (text.length > MAX_TEXT_LENGTH) throw new Error(`Messages are limited to ${MAX_TEXT_LENGTH} characters`);
    const key = g.keys.get(g.epoch);
    if (!key) throw new Error('No key for the current epoch yet');
    const msg = await C.encryptMessage({
      groupKey: key, groupId, epoch: g.epoch, sender: this.username, signPriv: this.identity.signPriv, text,
    });
    await this.request('send', { msg });
    await this.#ingestMessage(msg);
    return msg.id;
  }

  async loadHistory(groupId) {
    const { messages } = await this.request('history', { groupId });
    for (const msg of messages) await this.#ingestMessage(msg);
    const g = this.groups.get(groupId);
    if (g) g.historyLoaded = true;
    this.#emit('message', { groupId });
  }

  /**
   * Accepts a message only if: its sender was a member of the signed state for
   * that epoch, the sender's signature verifies, and it decrypts under the
   * epoch key. Anything else is shown as a warning, never as content.
   */
  async #ingestMessage(msg) {
    if (!msg || typeof msg.id !== 'string' || this.seen.has(msg.id)) return;
    const g = this.groups.get(msg.groupId);
    if (!g) return;
    this.seen.add(msg.id);
    const entry = { id: msg.id, sender: msg.sender, ts: msg.ts, epoch: msg.epoch, text: null, error: null };
    try {
      const state = g.states[msg.epoch - 1];
      if (!state?.members.includes(msg.sender)) throw new Error('sender was not a member of this epoch');
      const sender = await this.getContact(msg.sender);
      if (!(await C.verifyMessage(msg, sender.signKey))) throw new Error('signature check failed');
      const key = g.keys.get(msg.epoch);
      if (!key) throw new Error('no key for this epoch');
      entry.text = await C.decryptMessage(msg, key);
    } catch (err) {
      entry.error = `Message rejected: ${err.message}`;
    }
    g.messages.push(entry);
    g.messages.sort((a, b) => a.ts - b.ts);
    this.#emit('message', { groupId: g.id, message: entry });
  }
}
