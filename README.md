# OrbiSphere Link

End-to-end encrypted **group** messaging web app. Every group has its own
encryption key, and that key is replaced whenever membership changes. The
server relays and stores only ciphertext and never holds a key that could
decrypt a message.

## Quick start

```bash
npm install
npm start            # http://localhost:8080
npm test             # crypto unit tests + end-to-end tests against a real server
```

The UI follows the [spherechain.space](https://spherechain.space) visual language (dark navy, SphereChain red, mono labels, pill buttons); groups are called *circles*.

Open the app in two different browsers (or one normal + one private window),
create an identity in each, then create a group and add the other user.

Environment variables: `PORT` (default `8080`), `HOST` (default `0.0.0.0`),
`DATA_FILE` (default `data/db.json`).

> WebCrypto only works in a secure context. In production, serve over **HTTPS**
> (for example behind a TLS-terminating reverse proxy); `localhost` works for development.

## How the encryption works

All cryptography runs in the browser through the standard WebCrypto API (no
custom primitives). The code is in `public/js/crypto.js`.

| Piece | Algorithm | Notes |
|---|---|---|
| User identity | ECDSA P-256 (signing) + ECDH P-256 (key agreement) | Generated in the browser as **non-extractable** keys and kept in IndexedDB |
| Login | Signature over a server nonce and both public keys | No passwords; the username is bound to its keys on first use |
| Group key | Random 256-bit AES-GCM key per *epoch* | A new epoch (and key) for every add, remove, leave, or manual rotation |
| Key distribution | Ephemeral ECDH → HKDF-SHA256 → AES-256-GCM, one envelope per member | Each envelope is **signed by the group owner** |
| Group membership | Owner-signed state chain `epoch 1..n` | Clients verify the whole chain, so the server can't add members on its own |
| Messages | AES-256-GCM under the epoch key; header (group, epoch, sender, time) as AAD | Each message is also **signed by its sender**, so members can't impersonate each other |
| Identity verification | 60-digit safety numbers, trust on first use | A changed key is detected and blocks encryption to that user |

### Group lifecycle

1. **Create:** the owner signs `{groupId, name, owner, members, epoch: 1}`,
   generates a group key, and wraps it to every member's public key.
2. **Add member:** this starts a new epoch with a new key. New members get only
   the new key, so they **cannot read earlier history**.
3. **Remove member:** this starts a new epoch whose key goes only to the
   remaining members. The removed member stops receiving messages and holds no
   key for new ones.
4. **Leave:** the server stops relaying to the person who left immediately.
   The owner's client sees this and **rotates the key automatically**.
5. **Send:** a client encrypts with the current epoch's key. The server rejects
   messages that use an outdated epoch, carry a sender name that doesn't match
   the logged-in user, or have an invalid signature.

### Threat model

Protected against a malicious or compromised **server**, which cannot:
- read messages or group keys (it only sees ciphertext and public keys)
- add itself or anyone else to a group (membership is signed by the owner)
- hand members a group key of its own (envelopes are signed by the owner)
- forge or alter messages (AEAD plus a sender signature)
- swap a contact's key unnoticed (keys are pinned, and safety numbers can be checked out of band)

Also protected against:
- **removed members** reading new messages, and new members reading old messages
- **group members** impersonating each other
- **XSS escalation:** a strict Content Security Policy blocks inline scripts,
  all user content is rendered with `textContent`, and private keys are non-extractable
- cross-site WebSocket hijacking (Origin check), oversized payloads, and request floods (per-connection rate limit)

The server **can still see metadata**: who is in which group, who sent a
message, when, and roughly how long it was.

### Known limitations and roadmap

This is a solid foundation, not yet a replacement for Signal. Before relying on it for high-risk use:

- **No per-message forward secrecy.** Someone who steals a device's stored
  group keys can read that group's history for the epochs they cover. Rotating
  the key limits the exposure. The production-grade path is
  [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420), whose TreeKEM ratchet
  gives forward secrecy and post-compromise security, and which scales better
  than wrapping the key separately for every member.
- **One device per account.** The identity lives in a single browser.
  Clearing site data loses it, and the username can't be reclaimed. Multi-device
  support and encrypted backups are next steps.
- **Only the owner manages membership.** Admin roles would need signed delegation.
- **Delivering web-app code is a trust point:** whoever serves the JavaScript
  could serve a malicious version. Mitigations include a packaged desktop or
  mobile app, Subresource Integrity, and reproducible builds.
- This code has not had an independent security audit.

## Project layout

```
public/js/crypto.js    E2EE primitives (shared by browser, server and tests)
public/js/protocol.js  shared constants and validation
public/js/client.js    client core: auth, key pinning, group verification, encrypt/decrypt
public/js/app.js       browser UI
public/js/idb.js       IndexedDB key store
public/js/rain.js      decorative falling-glyph backdrop for the landing screen
server/server.js       HTTP + WebSocket relay (validates and verifies, cannot decrypt)
server/store.js        JSON-file persistence
test/                  unit + end-to-end tests (node:test)
```
