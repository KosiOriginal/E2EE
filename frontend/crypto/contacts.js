'use strict';
/**
 * contacts.js — persistent contact list + per-contact conversation state.
 *
 * Stored in localStorage, keyed by fingerprint, so:
 *  - you can give friends nicknames instead of remembering keys
 *  - your conversation with each friend survives page reloads,
 *    because the ratchet state (not just the identity) is saved
 *  - refreshing the page no longer desyncs you from your friend
 */

const CONTACTS_KEY = 'secnet_contacts_v1';

function loadContacts() {
  const raw = localStorage.getItem(CONTACTS_KEY);
  return raw ? JSON.parse(raw) : {};
}

function saveContacts(contacts) {
  try {
    localStorage.setItem(CONTACTS_KEY, JSON.stringify(contacts));
  } catch (err) {
    console.error('Storage full — dropping oldest media message to make room:', err);
    for (const fp of Object.keys(contacts)) {
      const msgs = contacts[fp].messages;
      const idx = msgs.findIndex((m) => m.kind !== 'text');
      if (idx !== -1) {
        msgs.splice(idx, 1);
        break;
      }
    }
    try {
      localStorage.setItem(CONTACTS_KEY, JSON.stringify(contacts));
    } catch (err2) {
      console.error('Still could not save contacts — storage is critically full:', err2);
    }
  }
}

function addContact(fingerprint, name, publicKeyB64) {
  const contacts = loadContacts();
  contacts[fingerprint] = {
    name,
    publicKey: publicKeyB64,
    ratchetState: null, // filled in once a session is established
    messages: [], // { who: 'me'|'friend', kind: 'text'|'image'|'voice', content, ts }
  };
  saveContacts(contacts);
  return contacts[fingerprint];
}

function getContact(fingerprint) {
  return loadContacts()[fingerprint] || null;
}

function updateRatchetState(fingerprint, ratchetStateJSON) {
  const contacts = loadContacts();
  if (!contacts[fingerprint]) return;
  contacts[fingerprint].ratchetState = ratchetStateJSON;
  saveContacts(contacts);
}

function appendMessageToHistory(fingerprint, message) {
  const contacts = loadContacts();
  if (!contacts[fingerprint]) return;
  contacts[fingerprint].messages.push(message);
  saveContacts(contacts);
}

function listContacts() {
  const contacts = loadContacts();
  return Object.entries(contacts).map(([fingerprint, data]) => ({ fingerprint, ...data }));
}

function removeContact(fingerprint) {
  const contacts = loadContacts();
  delete contacts[fingerprint];
  saveContacts(contacts);
}

window.SecnetContacts = {
  loadContacts,
  addContact,
  getContact,
  updateRatchetState,
  appendMessageToHistory,
  listContacts,
  removeContact,
};
