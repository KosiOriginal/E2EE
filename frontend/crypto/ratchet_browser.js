'use strict';
/**
 * ratchet_browser.js — Double ratchet using the Web Crypto API
 * (works identically in the browser and here in Node, since Node
 * exposes the same standard `crypto.subtle` interface for testing).
 *
 * Browser crypto is promise-based, so every function here is async —
 * that's the only real difference from the server-side version.
 */

async function chainStep(chainKeyBytes) {
  const baseKey = await crypto.subtle.importKey('raw', chainKeyBytes, 'HKDF', false, ['deriveBits']);

  const nextChainKeyBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('chain-key') },
    baseKey,
    256
  );
  const messageKeyBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('message-key') },
    baseKey,
    256
  );

  return {
    nextChainKey: new Uint8Array(nextChainKeyBits),
    messageKey: new Uint8Array(messageKeyBits),
  };
}

class RatchetBrowser {
  constructor(sharedSecretBytes) {
    this.chainKey = sharedSecretBytes;
    this.messageCount = 0;
    this.skippedKeys = new Map();
  }

  async encrypt(plaintextBytes, associatedDataBytes = new Uint8Array(0)) {
    const { nextChainKey, messageKey } = await chainStep(this.chainKey);
    this.chainKey = nextChainKey; // old key discarded — forward secrecy
    const index = this.messageCount++;

    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await crypto.subtle.importKey('raw', messageKey, 'AES-GCM', false, ['encrypt']);
    const ciphertextBuf = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: associatedDataBytes },
      aesKey,
      plaintextBytes
    );

    return { index, nonce, ciphertext: new Uint8Array(ciphertextBuf) };
  }

  async decrypt(packet, associatedDataBytes = new Uint8Array(0)) {
    const { index, nonce, ciphertext } = packet;
    let messageKey;

    if (this.skippedKeys.has(index)) {
      messageKey = this.skippedKeys.get(index);
      this.skippedKeys.delete(index);
    } else {
      while (this.messageCount <= index) {
        const { nextChainKey, messageKey: mk } = await chainStep(this.chainKey);
        this.chainKey = nextChainKey;
        this.skippedKeys.set(this.messageCount, mk);
        this.messageCount++;
      }
      messageKey = this.skippedKeys.get(index);
      this.skippedKeys.delete(index);
    }

    const aesKey = await crypto.subtle.importKey('raw', messageKey, 'AES-GCM', false, ['decrypt']);
    const plaintextBuf = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: associatedDataBytes },
      aesKey,
      ciphertext
    );
    return new Uint8Array(plaintextBuf);
  }
}

window.SecnetRatchet = { RatchetBrowser };
