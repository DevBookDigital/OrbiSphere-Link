// Browser UI. All rendering of user-controlled data uses textContent, never innerHTML.

import { OrbiClient, KeyChangedError } from './client.js';
import { openStore } from './idb.js';
import { startRain } from './rain.js';

const $ = (id) => document.getElementById(id);
const wsUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`;

let client;
let activeGroupId = null;
let reconnectDelay = 1000;
let stopped = false;

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node[k] = v;
  }
  for (const child of children) if (child != null) node.append(child);
  return node;
}

function toast(message, kind = 'info') {
  const node = el('div', { class: `toast ${kind}`, textContent: message });
  $('toasts').append(node);
  setTimeout(() => node.remove(), kind === 'error' ? 8000 : 4000);
}

async function guard(fn) {
  try {
    await fn();
  } catch (err) {
    console.error(err);
    toast(err.message, err instanceof KeyChangedError ? 'error' : 'warn');
  }
}

const splitNames = (s) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

// ------------------------------------------------------------ connection

function setStatus(text, ok) {
  const s = $('conn-status');
  s.textContent = text;
  s.classList.toggle('ok', ok);
}

async function connect() {
  setStatus('connecting…', false);
  try {
    await client.connect();
    reconnectDelay = 1000;
    setStatus('secure', true);
    if (activeGroupId) await client.loadHistory(activeGroupId);
  } catch (err) {
    if (/already taken/.test(err.message)) {
      // The fresh identity we just created can't claim this name; discard it and start over.
      stopped = true;
      await client.store.del('identity');
      toast('That username is taken by someone else. Pick another one.', 'error');
      setTimeout(() => location.reload(), 2500);
      return;
    }
    setStatus('offline', false);
  }
}

function scheduleReconnect() {
  if (stopped) return;
  setStatus('offline', false);
  setTimeout(connect, reconnectDelay);
  reconnectDelay = Math.min(reconnectDelay * 2, 30_000);
}

// ------------------------------------------------------------ rendering

function renderGroups() {
  const list = $('group-list');
  list.replaceChildren();
  const groups = [...client.groups.values()].sort((a, b) => a.name.localeCompare(b.name));
  if (groups.length === 0) list.append(el('li', { class: 'muted small', textContent: 'No circles yet.' }));
  for (const g of groups) {
    list.append(el('li', {},
      el('button', { class: `group ${g.id === activeGroupId ? 'active' : ''}`, onclick: () => openGroup(g.id) },
        el('span', { class: 'avatar', textContent: g.name.trim().slice(0, 2) }),
        el('span', { class: 'group-text' },
          el('span', { class: 'group-name', textContent: g.name }),
          el('span', { class: 'group-meta', textContent: `${g.latest.members.length} members · epoch ${g.epoch}` })))));
  }
  if (activeGroupId && !client.groups.has(activeGroupId)) {
    activeGroupId = null;
    renderChat();
  } else if (activeGroupId) {
    renderChatHeader();
    renderMembers();
  }
}

function renderChatHeader() {
  const g = client.groups.get(activeGroupId);
  $('chat-title').textContent = g.name;
  $('chat-epoch').textContent = String(g.epoch);
}

function renderMessages() {
  const g = client.groups.get(activeGroupId);
  const list = $('messages');
  const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 80;
  list.replaceChildren();
  for (const m of g?.messages ?? []) {
    const mine = m.sender === client.username;
    list.append(el('li', { class: `msg ${mine ? 'mine' : ''} ${m.error ? 'bad' : ''}` },
      el('div', { class: 'meta' },
        el('span', { class: 'sender', textContent: mine ? 'You' : m.sender }),
        el('time', { textContent: new Date(m.ts).toLocaleString(), title: `epoch ${m.epoch}` })),
      el('div', { class: 'body', textContent: m.error ?? m.text })));
  }
  if (nearBottom) list.scrollTop = list.scrollHeight;
}

async function renderMembers() {
  const g = client.groups.get(activeGroupId);
  if (!g) return;
  const isOwner = g.owner === client.username;
  $('owner-tools').hidden = !isOwner;
  $('leave-group').hidden = isOwner;
  const list = $('member-list');
  const rows = await Promise.all(g.latest.members.map(async (name) => {
    const contact = await client.getContact(name).catch(() => null);
    const left = !g.serverMembers.includes(name);
    const info = el('div', { class: 'member-info' },
      el('div', {},
        el('strong', { textContent: name }),
        name === g.owner ? el('span', { class: 'badge', textContent: 'owner' }) : null,
        name === client.username ? el('span', { class: 'badge', textContent: 'you' }) : null,
        contact?.verified && name !== client.username ? el('span', { class: 'badge ok', textContent: 'verified' }) : null,
        left ? el('span', { class: 'badge warn', textContent: 'left · rotating key' }) : null));
    const li = el('li', { class: 'member' }, el('span', { class: 'avatar', textContent: name.slice(0, 2) }), info);
    if (name !== client.username) {
      const actions = el('div', { class: 'actions' },
        el('button', { class: 'link', textContent: 'Safety number', onclick: () => showSafety(name) }),
        el('button', {
          class: 'link',
          textContent: contact?.verified ? 'Unverify' : 'Mark verified',
          onclick: () => guard(() => client.setVerified(name, !contact?.verified)),
        }),
        isOwner ? el('button', {
          class: 'link danger',
          textContent: 'Remove',
          onclick: () => guard(async () => {
            if (!confirm(`Remove ${name}? The circle key will be rotated so they can't read new messages.`)) return;
            await client.removeMember(g.id, name);
            toast(`${name} removed. New key distributed.`);
          }),
        }) : null);
      info.append(actions);
    }
    return li;
  }));
  if (activeGroupId === g.id) list.replaceChildren(...rows);
}

function renderChat() {
  const has = Boolean(activeGroupId);
  $('empty-state').hidden = has;
  $('chat-view').hidden = !has;
  if (!has) {
    $('members-panel').hidden = true;
    return;
  }
  renderChatHeader();
  renderMessages();
  renderMembers();
}

async function openGroup(id) {
  activeGroupId = id;
  renderGroups();
  renderChat();
  if (matchMedia('(max-width: 860px)').matches) $('chat-view').scrollIntoView({ block: 'start' });
  const g = client.groups.get(id);
  if (!g.historyLoaded) await guard(() => client.loadHistory(id));
  $('compose-text').focus();
}

async function showSafety(name) {
  const number = name === client.username ? await client.myFingerprint() : await client.fingerprintOf(name);
  $('safety-title').textContent = name === client.username ? 'Your safety number' : `Safety number for ${name}`;
  $('safety-number').textContent = number;
  $('safety-dialog').showModal();
}

// ------------------------------------------------------------ wiring

function bindUi() {
  $('me-name').textContent = client.username;
  $('show-my-safety').addEventListener('click', () => showSafety(client.username));

  $('new-group-form').addEventListener('submit', (e) => {
    e.preventDefault();
    guard(async () => {
      const g = await client.createGroup($('new-group-name').value, splitNames($('new-group-members').value));
      e.target.reset();
      toast(`Circle "${g.name}" created with a fresh encryption key.`);
      openGroup(g.id);
    });
  });

  $('compose').addEventListener('submit', (e) => {
    e.preventDefault();
    const box = $('compose-text');
    const text = box.value;
    if (!text.trim() || !activeGroupId) return;
    guard(async () => {
      await client.send(activeGroupId, text);
      box.value = '';
      box.style.height = '';
    });
  });
  $('compose-text').addEventListener('input', (e) => {
    e.target.style.height = 'auto';
    e.target.style.height = `${e.target.scrollHeight + 2}px`;
  });
  $('compose-text').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      $('compose').requestSubmit();
    }
  });

  $('toggle-members').addEventListener('click', () => {
    $('members-panel').hidden = !$('members-panel').hidden;
  });

  $('add-member-form').addEventListener('submit', (e) => {
    e.preventDefault();
    guard(async () => {
      await client.addMembers(activeGroupId, splitNames($('add-member-name').value));
      e.target.reset();
      toast('Members added. A new circle key was generated; they cannot read earlier messages.');
    });
  });

  $('rotate-key').addEventListener('click', () => guard(async () => {
    await client.rotateKey(activeGroupId);
    toast('Circle key rotated.');
  }));

  $('leave-group').addEventListener('click', () => guard(async () => {
    if (!confirm('Leave this circle? You will stop receiving messages.')) return;
    await client.leave(activeGroupId);
    activeGroupId = null;
    renderChat();
  }));

  client.addEventListener('groups', renderGroups);
  client.addEventListener('message', (e) => {
    if (e.detail?.groupId === activeGroupId) renderMessages();
  });
  client.addEventListener('removed', (e) => {
    const g = e.detail?.groupId;
    if (g === activeGroupId) toast('You are no longer a member of this circle.', 'warn');
  });
  client.addEventListener('keychange', (e) => toast(
    `WARNING: ${e.detail.username}'s identity key changed. Messages to them are blocked until you re-verify.`, 'error'));
  client.addEventListener('error', (e) => toast(e.detail?.message ?? 'Something went wrong', 'warn'));
  client.addEventListener('disconnected', scheduleReconnect);
}

async function start() {
  if (!globalThis.crypto?.subtle || !globalThis.indexedDB) {
    document.body.textContent = 'This browser lacks WebCrypto or IndexedDB (they require HTTPS or localhost).';
    return;
  }
  const store = await openStore();
  client = new OrbiClient({ url: wsUrl, store });

  if (!(await client.loadIdentity())) {
    $('setup').hidden = false;
    startRain($('rain'));
    $('setup-form').addEventListener('submit', (e) => {
      e.preventDefault();
      guard(async () => {
        await client.createIdentity($('setup-username').value);
        $('setup').hidden = true;
        launch();
      });
    });
    return;
  }
  launch();
}

function launch() {
  $('app').hidden = false;
  bindUi();
  renderGroups();
  renderChat();
  connect();
}

start();
