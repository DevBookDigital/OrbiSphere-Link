// OrbiSphere Link relay server.
//
// The server is deliberately "dumb": it authenticates users by their public
// signing key, relays ciphertext, and stores signed group metadata. It never
// sees a group key or a plaintext message. It still verifies every signature
// it can, so a misbehaving client cannot spoof another user through it.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { importSignPub, importDhPub, verifyObj, verifyMessage, toB64 } from '../public/js/crypto.js';
import {
  USERNAME_RE, GROUP_ID_RE, MAX_GROUP_MEMBERS, MAX_GROUP_NAME, MAX_TEXT_LENGTH, normalizeMembers,
} from '../public/js/protocol.js';
import { Store } from './store.js';

const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');
const HISTORY_LIMIT = 200;
const MAX_PAYLOAD_BYTES = 512 * 1024;
const RATE_LIMIT_PER_10S = 100;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    + "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

class ClientError extends Error {}

function check(cond, message) {
  if (!cond) throw new ClientError(message);
}

const isB64 = (s, max = 4096) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9_-]+$/.test(s);
const isUser = (s) => typeof s === 'string' && USERNAME_RE.test(s);
const isEpoch = (n) => Number.isSafeInteger(n) && n >= 1;

// ------------------------------------------------------------ shape checks

/** Returns exactly the signed fields of a group state, rejecting anything malformed. */
function parseState(s) {
  check(s && typeof s === 'object', 'state required');
  const state = {
    v: s.v, groupId: s.groupId, name: s.name, owner: s.owner, members: s.members, epoch: s.epoch, ts: s.ts,
  };
  check(state.v === 1, 'unsupported state version');
  check(typeof state.groupId === 'string' && GROUP_ID_RE.test(state.groupId), 'bad groupId');
  check(typeof state.name === 'string' && state.name.trim().length > 0 && state.name.length <= MAX_GROUP_NAME, 'bad group name');
  check(isUser(state.owner), 'bad owner');
  check(Array.isArray(state.members) && state.members.length >= 1 && state.members.length <= MAX_GROUP_MEMBERS, 'bad members');
  check(state.members.every(isUser), 'bad member name');
  check(JSON.stringify(normalizeMembers(state.members)) === JSON.stringify(state.members), 'members must be sorted and unique');
  check(state.members.includes(state.owner), 'owner must be a member');
  check(isEpoch(state.epoch), 'bad epoch');
  check(Number.isSafeInteger(state.ts), 'bad ts');
  return state;
}

function parseEnvelope(e, state, recipient) {
  check(e && typeof e === 'object', `missing key envelope for ${recipient}`);
  const env = {
    v: e.v, groupId: e.groupId, epoch: e.epoch, sender: e.sender, recipient: e.recipient,
    ephPub: e.ephPub, iv: e.iv, ct: e.ct, sig: e.sig,
  };
  check(env.v === 1 && env.groupId === state.groupId && env.epoch === state.epoch
    && env.sender === state.owner && env.recipient === recipient, `key envelope for ${recipient} does not match state`);
  check(isB64(env.ephPub, 128) && isB64(env.iv, 32) && isB64(env.ct, 128) && isB64(env.sig, 256), 'malformed key envelope');
  return env;
}

function parseMessage(m) {
  check(m && typeof m === 'object', 'msg required');
  const msg = {
    v: m.v, id: m.id, groupId: m.groupId, epoch: m.epoch, sender: m.sender, ts: m.ts, iv: m.iv, ct: m.ct, sig: m.sig,
  };
  check(msg.v === 1, 'unsupported message version');
  check(isB64(msg.id, 32) && isB64(msg.iv, 32) && isB64(msg.sig, 256), 'malformed message');
  // Base64 of AES-GCM ciphertext of a JSON wrapper around the text, with headroom for multi-byte chars.
  check(isB64(msg.ct, MAX_TEXT_LENGTH * 6), 'message too large');
  check(typeof msg.groupId === 'string' && GROUP_ID_RE.test(msg.groupId), 'bad groupId');
  check(isEpoch(msg.epoch) && Number.isSafeInteger(msg.ts) && isUser(msg.sender), 'malformed message');
  return msg;
}

// ------------------------------------------------------------ server

export async function createServer({ port = 8080, host = '0.0.0.0', dataFile = null, log = console.log } = {}) {
  const store = new Store(dataFile);
  await store.load();

  /** username -> Set<conn> */
  const online = new Map();
  const signKeyCache = new Map();

  async function signKeyOf(username) {
    let key = signKeyCache.get(username);
    if (!key) {
      const user = store.users.get(username);
      check(user, `unknown user ${username}`);
      key = await importSignPub(user.signPub);
      signKeyCache.set(username, key);
    }
    return key;
  }

  function push(username, payload, except) {
    const data = JSON.stringify(payload);
    for (const conn of online.get(username) ?? []) {
      if (conn !== except && conn.ws.readyState === conn.ws.OPEN) conn.ws.send(data);
    }
  }

  /** What one member is allowed to see of a group: all signed states, but only their own key envelopes. */
  function groupView(group, username) {
    const envelopes = {};
    for (const [epoch, byUser] of group.envelopes) {
      if (byUser[username]) envelopes[epoch] = byUser[username];
    }
    return {
      groupId: group.groupId,
      states: group.states,
      envelopes,
      members: group.members,
      needsRekey: group.needsRekey,
    };
  }

  function requireMember(groupId, username) {
    const group = typeof groupId === 'string' ? store.groups.get(groupId) : undefined;
    check(group && group.members.includes(username), 'no such group');
    return group;
  }

  async function verifyEpoch({ state: rawState, stateSig, envelopes: rawEnvelopes }) {
    const state = parseState(rawState);
    check(isB64(stateSig, 256), 'bad stateSig');
    check(rawEnvelopes && typeof rawEnvelopes === 'object', 'envelopes required');
    check(Object.keys(rawEnvelopes).length === state.members.length, 'need exactly one key envelope per member');
    for (const member of state.members) check(store.users.has(member), `unknown user ${member}`);
    const ownerKey = await signKeyOf(state.owner);
    check(await verifyObj(ownerKey, stateSig, state), 'invalid group state signature');
    const envelopes = {};
    for (const member of state.members) {
      const env = parseEnvelope(rawEnvelopes[member], state, member);
      const { sig, ...body } = env;
      check(await verifyObj(ownerKey, sig, body), `invalid key envelope signature for ${member}`);
      envelopes[member] = env;
    }
    return { state, stateSig, envelopes };
  }

  const handlers = {
    async auth(conn, m) {
      check(!conn.user, 'already authenticated');
      check(isUser(m.username), 'invalid username');
      check(isB64(m.signPub, 128) && isB64(m.dhPub, 128), 'invalid public keys');
      let signKey;
      try {
        signKey = await importSignPub(m.signPub);
        await importDhPub(m.dhPub);
      } catch {
        throw new ClientError('invalid public keys');
      }
      // The signature binds the nonce (anti-replay) and both public keys (key ownership).
      const body = { purpose: 'orbisphere-auth', v: 1, nonce: conn.nonce, username: m.username, signPub: m.signPub, dhPub: m.dhPub };
      check(await verifyObj(signKey, m.sig, body), 'authentication signature invalid');

      const existing = store.users.get(m.username);
      if (existing) {
        check(existing.signPub === m.signPub && existing.dhPub === m.dhPub, 'username is already taken');
      } else {
        store.users.set(m.username, { signPub: m.signPub, dhPub: m.dhPub, createdAt: Date.now() });
        store.scheduleSave();
        log(`registered ${m.username}`);
      }
      conn.user = m.username;
      if (!online.has(conn.user)) online.set(conn.user, new Set());
      online.get(conn.user).add(conn);
      return { username: conn.user };
    },

    async lookup(conn, m) {
      check(Array.isArray(m.usernames) && m.usernames.length <= MAX_GROUP_MEMBERS, 'bad usernames');
      const users = {};
      for (const name of m.usernames) {
        const u = isUser(name) && store.users.get(name);
        if (u) users[name] = { signPub: u.signPub, dhPub: u.dhPub };
      }
      return { users };
    },

    async sync(conn) {
      const groups = [];
      for (const group of store.groups.values()) {
        if (group.members.includes(conn.user)) groups.push(groupView(group, conn.user));
      }
      return { groups };
    },

    async createGroup(conn, m) {
      const epoch = await verifyEpoch(m);
      const { state } = epoch;
      check(state.owner === conn.user, 'only the owner can create a group');
      check(state.epoch === 1, 'new groups start at epoch 1');
      check(!store.groups.has(state.groupId), 'group already exists');
      const group = {
        groupId: state.groupId,
        owner: state.owner,
        epoch: 1,
        states: [{ state, stateSig: epoch.stateSig }],
        envelopes: new Map([[1, epoch.envelopes]]),
        members: state.members,
        needsRekey: false,
        left: [],
      };
      store.groups.set(group.groupId, group);
      store.scheduleSave();
      for (const member of group.members) push(member, { t: 'group', group: groupView(group, member) }, conn);
      return { group: groupView(group, conn.user) };
    },

    // Starts a new epoch: used to add members, remove members, or just rotate the key.
    async rekey(conn, m) {
      const epoch = await verifyEpoch(m);
      const { state } = epoch;
      // No awaits below this line, so the check-and-commit is atomic.
      const group = requireMember(state.groupId, conn.user);
      check(group.owner === conn.user && state.owner === group.owner, 'only the group owner can change membership');
      check(state.epoch === group.epoch + 1, `stale epoch: group is at ${group.epoch}`);
      const rejoined = state.members.filter((u) => group.left.includes(u));
      check(rejoined.length === 0, `${rejoined.join(', ')} left the group; refresh before changing membership`);

      const removed = group.members.filter((u) => !state.members.includes(u));
      group.epoch = state.epoch;
      group.states.push({ state, stateSig: epoch.stateSig });
      group.envelopes.set(state.epoch, epoch.envelopes);
      group.members = state.members;
      group.needsRekey = false;
      group.left = [];
      store.scheduleSave();

      for (const member of group.members) push(member, { t: 'group', group: groupView(group, member) }, conn);
      for (const user of removed) push(user, { t: 'removed', groupId: group.groupId });
      return { group: groupView(group, conn.user) };
    },

    async leave(conn, m) {
      const group = requireMember(m.groupId, conn.user);
      check(group.owner !== conn.user, 'the owner cannot leave their own group');
      group.members = group.members.filter((u) => u !== conn.user);
      // Stop relaying to the leaver immediately; the owner's client rotates the
      // key as soon as it sees this flag so the leaver's old key becomes useless.
      group.needsRekey = true;
      group.left.push(conn.user);
      store.scheduleSave();
      for (const member of group.members) push(member, { t: 'group', group: groupView(group, member) });
      push(conn.user, { t: 'removed', groupId: group.groupId }, conn);
      return {};
    },

    async send(conn, m) {
      const msg = parseMessage(m.msg);
      check(msg.sender === conn.user, 'sender mismatch');
      check(await verifyMessage(msg, await signKeyOf(conn.user)), 'invalid message signature');
      const group = requireMember(msg.groupId, conn.user);
      check(msg.epoch === group.epoch, `stale epoch: group is at ${group.epoch}`);
      const existing = store.messages.get(group.groupId);
      check(!existing?.some((x) => x.id === msg.id), 'duplicate message');
      msg.receivedAt = Date.now();
      store.addMessage(group.groupId, msg);
      for (const member of group.members) push(member, { t: 'msg', msg }, conn);
      return { receivedAt: msg.receivedAt };
    },

    async history(conn, m) {
      const group = requireMember(m.groupId, conn.user);
      // Only messages from epochs this user belonged to; they hold no key for the others anyway.
      const allowed = new Set(group.states.filter((s) => s.state.members.includes(conn.user)).map((s) => s.state.epoch));
      const messages = (store.messages.get(group.groupId) ?? []).filter((x) => allowed.has(x.epoch)).slice(-HISTORY_LIMIT);
      return { messages };
    },
  };

  async function dispatch(conn, m) {
    const handler = Object.hasOwn(handlers, m.t) ? handlers[m.t] : null;
    check(handler, 'unknown request');
    check(m.t === 'auth' || conn.user, 'not authenticated');
    return handler(conn, m);
  }

  // ---------------------------------------------------------- http + ws

  const httpServer = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        res.writeHead(405, SECURITY_HEADERS).end();
        return;
      }
      if (url.pathname === '/healthz') {
        res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': 'text/plain' }).end('ok');
        return;
      }
      const rel = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname).replace(/^\/+/, '');
      const file = path.resolve(PUBLIC_DIR, rel);
      if (!file.startsWith(PUBLIC_DIR + path.sep) || !MIME[path.extname(file)]) {
        res.writeHead(404, SECURITY_HEADERS).end('not found');
        return;
      }
      const body = await readFile(file);
      res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': MIME[path.extname(file)], 'Cache-Control': 'no-cache' });
      res.end(req.method === 'HEAD' ? undefined : body);
    } catch {
      res.writeHead(404, SECURITY_HEADERS).end('not found');
    }
  });

  const wss = new WebSocketServer({ server: httpServer, path: '/ws', maxPayload: MAX_PAYLOAD_BYTES });

  wss.on('connection', (ws, req) => {
    // Reject cross-site WebSocket hijacking: browsers always send Origin.
    const origin = req.headers.origin;
    let originHost = null;
    try {
      originHost = origin ? new URL(origin).host : null;
    } catch {
      originHost = '';
    }
    if (origin && originHost !== req.headers.host) {
      ws.close(1008, 'origin not allowed');
      return;
    }
    const conn = { ws, user: null, nonce: toB64(randomBytes(32)), queue: Promise.resolve(), window: Date.now(), count: 0 };
    ws.send(JSON.stringify({ t: 'challenge', nonce: conn.nonce }));

    ws.on('message', (data) => {
      const now = Date.now();
      if (now - conn.window > 10_000) {
        conn.window = now;
        conn.count = 0;
      }
      if (++conn.count > RATE_LIMIT_PER_10S) {
        ws.close(1008, 'rate limit');
        return;
      }
      let m;
      try {
        m = JSON.parse(data.toString());
      } catch {
        ws.close(1003, 'bad json');
        return;
      }
      if (!m || typeof m !== 'object') return;
      // Process one request at a time per connection to keep ordering predictable.
      conn.queue = conn.queue.then(async () => {
        let reply;
        try {
          reply = { t: 'res', rid: m.rid, ok: true, data: await dispatch(conn, m) };
        } catch (err) {
          if (!(err instanceof ClientError)) log('internal error', err);
          reply = { t: 'res', rid: m.rid, ok: false, error: err instanceof ClientError ? err.message : 'internal error' };
        }
        if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(reply));
      });
    });

    ws.on('close', () => {
      if (!conn.user) return;
      const set = online.get(conn.user);
      set?.delete(conn);
      if (set?.size === 0) online.delete(conn.user);
    });
  });

  await new Promise((resolve) => httpServer.listen(port, host, resolve));
  const actualPort = httpServer.address().port;

  return {
    port: actualPort,
    store,
    async close() {
      for (const client of wss.clients) client.terminate();
      await new Promise((resolve) => wss.close(resolve));
      await new Promise((resolve) => httpServer.close(resolve));
      await store.flush();
    },
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 8080);
  const dataFile = process.env.DATA_FILE ?? path.resolve(PUBLIC_DIR, '../data/db.json');
  const server = await createServer({ port, host: process.env.HOST ?? '0.0.0.0', dataFile });
  console.log(`OrbiSphere Link listening on http://localhost:${server.port}`);
  const shutdown = async () => {
    await server.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
