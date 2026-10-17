// End-to-end encryption primitives for OrbiSphere Link.
//
// Runs unchanged in the browser and in Node.js (>= 20) because it only uses
// the standard WebCrypto API. Nothing here talks to the network.
//
// Building blocks:
//   identity    ECDSA P-256 (signing) + ECDH P-256 (key agreement) per user
//   group key   random 256-bit AES-GCM key, one per group *epoch*
//   key wrap    ephemeral ECDH -> HKDF-SHA256 -> AES-256-GCM, signed by the group owner
//   messages    AES-256-GCM under the epoch key, header bound as AAD, signed by the sender

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

const SIGN_ALG = { name: 'ECDSA', namedCurve: 'P-256' };
const DH_ALG = { name: 'ECDH', namedCurve: 'P-256' };
const SIG_PARAMS = { name: 'ECDSA', hash: 'SHA-256' };
const WRAP_INFO = enc.encode('orbisphere/v1/group-key-wrap');
const FINGERPRINT_PREFIX = 'orbisphere/v1/fingerprint';
const GROUP_KEY_BYTES = 32;
const IV_BYTES = 12;

// ---------------------------------------------------------------- encoding

export function toB64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromB64(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('Invalid base64url');
  const s = atob(str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

/** Deterministic JSON (sorted keys) so both sides sign/verify identical bytes. */
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .filter((k) => value[k] !== undefined)
    .map((k) => JSON.stringify(k) + ':' + canonical(value[k]))
    .join(',') + '}';
}

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

// ---------------------------------------------------------------- identity

/**
 * Generates a new identity. Private keys are created non-extractable, so
 * page scripts (or an XSS payload) can use them but can never read them out.
 */
export async function generateIdentity() {
  const sign = await subtle.generateKey(SIGN_ALG, false, ['sign', 'verify']);
  const dh = await subtle.generateKey(DH_ALG, false, ['deriveBits']);
  return {
    signPriv: sign.privateKey,
    signPub: sign.publicKey,
    dhPriv: dh.privateKey,
    dhPub: dh.publicKey,
    signPubB64: toB64(await subtle.exportKey('raw', sign.publicKey)),
    dhPubB64: toB64(await subtle.exportKey('raw', dh.publicKey)),
  };
}

function rawPoint(b64) {
  const raw = fromB64(b64);
  if (raw.length !== 65 || raw[0] !== 4) throw new Error('Invalid P-256 public key');
  return raw;
}

export function importSignPub(b64) {
  return subtle.importKey('raw', rawPoint(b64), SIGN_ALG, true, ['verify']);
}

export function importDhPub(b64) {
  return subtle.importKey('raw', rawPoint(b64), DH_ALG, true, []);
}

export async function signObj(privKey, obj) {
  return toB64(await subtle.sign(SIG_PARAMS, privKey, enc.encode(canonical(obj))));
}

export async function verifyObj(pubKey, sigB64, obj) {
  try {
    return await subtle.verify(SIG_PARAMS, pubKey, fromB64(sigB64), enc.encode(canonical(obj)));
  } catch {
    return false;
  }
}

/**
 * Human-comparable fingerprint of a user's public identity. Two people read
 * these to each other (in person / on a call) to rule out a server that
 * swapped keys.
 */
export async function fingerprint(signPubB64, dhPubB64) {
  const digest = new Uint8Array(await subtle.digest('SHA-256',
    enc.encode(`${FINGERPRINT_PREFIX}|${signPubB64}|${dhPubB64}`)));
  const groups = [];
  for (let i = 0; i < 30; i += 5) {
    // 5 bytes -> 40 bits -> 10 decimal digits, shown as two blocks of 5.
    let n = 0n;
    for (let j = 0; j < 5; j++) n = (n << 8n) | BigInt(digest[i + j]);
    const digits = (n % 10_000_000_000n).toString().padStart(10, '0');
    groups.push(digits.slice(0, 5), digits.slice(5));
  }
  return groups.join(' ');
}

// ---------------------------------------------------------------- group keys

export function newGroupKeyBytes() {
  return randomBytes(GROUP_KEY_BYTES);
}

export function importGroupKey(bytes) {
  return subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function deriveWrapKey(myDhPriv, theirDhPub, ephPubB64, recipientDhPubB64) {
  const shared = await subtle.deriveBits({ name: 'ECDH', public: theirDhPub }, myDhPriv, 256);
  const ikm = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(`${ephPubB64}|${recipientDhPubB64}`), info: WRAP_INFO },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Encrypts a group key to one member. A fresh ephemeral ECDH key is used per
 * envelope, and the envelope is signed by the sender (the group owner) so a
 * malicious server cannot slip members a key of its own choosing.
 */
export async function wrapGroupKey({ keyBytes, groupId, epoch, sender, recipient, recipientDhPubB64, senderSignPriv }) {
  const recipientPub = await importDhPub(recipientDhPubB64);
  const eph = await subtle.generateKey(DH_ALG, true, ['deriveBits']);
  const ephPub = toB64(await subtle.exportKey('raw', eph.publicKey));
  const kek = await deriveWrapKey(eph.privateKey, recipientPub, ephPub, recipientDhPubB64);
  const iv = randomBytes(IV_BYTES);
  const meta = { v: 1, groupId, epoch, sender, recipient, ephPub };
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(canonical(meta)) }, kek, keyBytes);
  const body = { ...meta, iv: toB64(iv), ct: toB64(ct) };
  return { ...body, sig: await signObj(senderSignPriv, body) };
}

/** Verifies and decrypts a key envelope, returning a non-extractable AES-GCM key. */
export async function unwrapGroupKey({ envelope, groupId, epoch, recipient, sender, myDhPriv, myDhPubB64, senderSignPub }) {
  const { v, sig, ...rest } = envelope;
  const body = { v, groupId: rest.groupId, epoch: rest.epoch, sender: rest.sender, recipient: rest.recipient,
    ephPub: rest.ephPub, iv: rest.iv, ct: rest.ct };
  if (body.v !== 1 || body.groupId !== groupId || body.epoch !== epoch
      || body.recipient !== recipient || body.sender !== sender) {
    throw new Error('Key envelope does not match the expected group, epoch or sender');
  }
  if (!(await verifyObj(senderSignPub, sig, body))) throw new Error('Key envelope signature is invalid');
  const ephPub = await importDhPub(body.ephPub);
  const kek = await deriveWrapKey(myDhPriv, ephPub, body.ephPub, myDhPubB64);
  const { iv, ct, ...meta } = body;
  const keyBytes = new Uint8Array(await subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(iv), additionalData: enc.encode(canonical(meta)) }, kek, fromB64(ct)));
  if (keyBytes.length !== GROUP_KEY_BYTES) throw new Error('Unexpected group key length');
  const key = await importGroupKey(keyBytes);
  keyBytes.fill(0);
  return key;
}

// ---------------------------------------------------------------- messages

/**
 * Encrypts a chat message for a group epoch. The cleartext header (who, where,
 * when) is authenticated as AAD and the whole thing is signed by the sender,
 * so other group members cannot impersonate each other.
 */
export async function encryptMessage({ groupKey, groupId, epoch, sender, signPriv, text }) {
  const header = { v: 1, id: toB64(randomBytes(16)), groupId, epoch, sender, ts: Date.now() };
  const iv = randomBytes(IV_BYTES);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(canonical(header)) },
    groupKey, enc.encode(JSON.stringify({ text })));
  const body = { ...header, iv: toB64(iv), ct: toB64(ct) };
  return { ...body, sig: await signObj(signPriv, body) };
}

export function verifyMessage(msg, senderSignPub) {
  // Pick the signed fields explicitly: relays may annotate messages (e.g. receivedAt).
  const { v, id, groupId, epoch, sender, ts, iv, ct } = msg;
  return verifyObj(senderSignPub, msg.sig, { v, id, groupId, epoch, sender, ts, iv, ct });
}

export async function decryptMessage(msg, groupKey) {
  const { v, id, groupId, epoch, sender, ts, iv, ct } = msg;
  const header = { v, id, groupId, epoch, sender, ts };
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(iv), additionalData: enc.encode(canonical(header)) }, groupKey, fromB64(ct));
  const { text } = JSON.parse(dec.decode(pt));
  if (typeof text !== 'string') throw new Error('Malformed message payload');
  return text;
}
