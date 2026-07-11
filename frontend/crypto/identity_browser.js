'use strict';
/**
 * identity_browser.js — Device identity for the browser.
 *
 * Uses TweetNaCl.js for the X25519 keypair (works identically in
 * every browser — no gaps like Safari currently has with native
 * Web Crypto X25519). Web Crypto itself is still used for HKDF and
 * AES-GCM in ratchet_browser.js, since those ARE universally
 * supported.
 *
 * NOTE on scope: this does a single direct Diffie-Hellman between
 * two identity keys to seed the ratchet — simpler than the full
 * X3DH handshake (identity.js/handshake.js on the server side
 * already have that logic ready to port here later). This version
 * still gets you real end-to-end encryption + forward secrecy; it
 * just skips the "start a conversation with someone who's currently
 * offline" async handshake for now. Good enough to get a working
 * chat going, upgradeable later.
 */

const STORAGE_KEY = 'secnet_identity_v1';

function toB64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
function fromB64(str) {
  return new Uint8Array(atob(str).split('').map((c) => c.charCodeAt(0)));
}

function loadOrCreateIdentity() {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) {
    const { publicKey, secretKey } = JSON.parse(saved);
    return { publicKey: fromB64(publicKey), secretKey: fromB64(secretKey) };
  }

  const keyPair = nacl.box.keyPair();
  localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({ publicKey: toB64(keyPair.publicKey), secretKey: toB64(keyPair.secretKey) })
  );
  return { publicKey: keyPair.publicKey, secretKey: keyPair.secretKey };
}

function fingerprint(publicKeyBytes) {
  // Human-verifiable ID. Read this aloud / compare with a friend in
  // person (or over a call you both trust) before chatting, so
  // nobody can quietly swap in a fake key (man-in-the-middle).
  const b32 = toB64(publicKeyBytes).replace(/[+/=]/g, '').toUpperCase();
  return b32.match(/.{1,4}/g).join('-');
}

// Direct ECDH between my identity and a friend's — seeds the ratchet.
// (See NOTE above re: this vs. full X3DH.)
async function deriveSharedSecret(mySecretKey, theirPublicKey) {
  const rawShared = nacl.scalarMult(mySecretKey, theirPublicKey); // 32 bytes

  // Run through HKDF for domain separation — never use a raw DH
  // output directly as a key.
  const baseKey = await crypto.subtle.importKey('raw', rawShared, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('secnet-direct-dh') },
    baseKey,
    256
  );
  return new Uint8Array(bits);
}

window.SecnetIdentity = { loadOrCreateIdentity, fingerprint, deriveSharedSecret, toB64, fromB64 };
