import { openDB } from 'idb';

const dbPromise = openDB('SecNetDB', 1, {
  upgrade(db) {
    // Таблица за контакти
    db.createObjectStore('contacts', { keyPath: 'id', autoIncrement: true });
    // Таблица за съобщения
    db.createObjectStore('messages', { keyPath: 'id', autoIncrement: true });
  },
});

export const saveContact = async (name, publicKey, sharedSecret) => {
  const db = await dbPromise;
  return db.add('contacts', { name, publicKey, sharedSecret, createdAt: new Date() });
};

export const getContacts = async () => {
  const db = await dbPromise;
  return db.getAll('contacts');
};
