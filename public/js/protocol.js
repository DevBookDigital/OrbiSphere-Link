// Constants and validation shared by the browser client and the relay server.

export const PROTOCOL_VERSION = 1;

// Must start with a letter so names like "__proto__" can never be used.
export const USERNAME_RE = /^[a-z][a-z0-9_.-]{2,31}$/;
export const GROUP_ID_RE = /^[A-Za-z0-9_-]{22}$/;
export const MAX_GROUP_MEMBERS = 100;
export const MAX_GROUP_NAME = 64;
export const MAX_TEXT_LENGTH = 8000;

export function normalizeUsername(name) {
  const n = String(name ?? '').trim().toLowerCase();
  if (!USERNAME_RE.test(n)) {
    throw new Error(`Invalid username "${name}": use 3-32 characters a-z, 0-9, "_", "." or "-", starting with a letter`);
  }
  return n;
}

/** Deduplicated, sorted member list. Sorting keeps the signed group state canonical. */
export function normalizeMembers(names) {
  const set = new Set(names.map(normalizeUsername));
  if (set.size > MAX_GROUP_MEMBERS) throw new Error(`Groups are limited to ${MAX_GROUP_MEMBERS} members`);
  return [...set].sort();
}
