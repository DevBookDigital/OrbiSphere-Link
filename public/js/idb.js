// Tiny IndexedDB key/value store. CryptoKey objects are stored as-is
// (structured clone), so non-extractable private keys stay non-extractable.

export function openStore(dbName = 'orbisphere-link') {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, 1);
    req.onupgradeneeded = () => req.result.createObjectStore('kv');
    req.onerror = () => reject(req.error);
    req.onsuccess = () => {
      const db = req.result;
      const run = (mode, fn) => new Promise((res, rej) => {
        const r = fn(db.transaction('kv', mode).objectStore('kv'));
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
      });
      resolve({
        get: (key) => run('readonly', (s) => s.get(key)),
        set: (key, value) => run('readwrite', (s) => s.put(value, key)).then(() => {}),
        del: (key) => run('readwrite', (s) => s.delete(key)).then(() => {}),
      });
    };
  });
}
