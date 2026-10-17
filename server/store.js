// Minimal persistent store. Everything in here is public keys, signed group
// metadata and ciphertext: the server never holds anything it could decrypt.

import { readFile, writeFile, rename, mkdir } from 'node:fs/promises';
import path from 'node:path';

const MAX_MESSAGES_PER_GROUP = 5000;
const SAVE_DELAY_MS = 250;

export class Store {
  constructor(file) {
    this.file = file;
    this.users = new Map(); // username -> { signPub, dhPub, createdAt }
    this.groups = new Map(); // groupId -> group record (see server.js)
    this.messages = new Map(); // groupId -> [msg]
    this.saveTimer = null;
    this.saving = Promise.resolve();
  }

  async load() {
    if (!this.file) return;
    let raw;
    try {
      raw = await readFile(this.file, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') return;
      throw err;
    }
    const data = JSON.parse(raw);
    this.users = new Map(data.users);
    this.groups = new Map(data.groups.map(([id, g]) => [id, { ...g, envelopes: new Map(g.envelopes) }]));
    this.messages = new Map(data.messages);
  }

  addMessage(groupId, msg) {
    const list = this.messages.get(groupId) ?? [];
    list.push(msg);
    if (list.length > MAX_MESSAGES_PER_GROUP) list.splice(0, list.length - MAX_MESSAGES_PER_GROUP);
    this.messages.set(groupId, list);
    this.scheduleSave();
  }

  scheduleSave() {
    if (!this.file || this.saveTimer) return;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      this.saving = this.saving.then(() => this.#write()).catch((err) => console.error('store save failed', err));
    }, SAVE_DELAY_MS);
  }

  async flush() {
    if (this.saveTimer) {
      clearTimeout(this.saveTimer);
      this.saveTimer = null;
      this.saving = this.saving.then(() => this.#write());
    }
    await this.saving;
  }

  async #write() {
    const data = {
      users: [...this.users],
      groups: [...this.groups].map(([id, g]) => [id, { ...g, envelopes: [...g.envelopes] }]),
      messages: [...this.messages],
    };
    await mkdir(path.dirname(this.file), { recursive: true });
    const tmp = `${this.file}.tmp`;
    await writeFile(tmp, JSON.stringify(data), { mode: 0o600 });
    await rename(tmp, this.file);
  }
}
