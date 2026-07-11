'use strict';
/**
 * ratchet.js — Simplified Double Ratchet.
 *
 * Derives a brand new encryption key for every message, then deletes
 * the old one. A device compromised today can't decrypt yesterday's
 * messages (forward secrecy). Also tolerates out-of-order delivery,
 * which happens constantly in mesh networks (messages take different
 * relay paths).
 *
 * NOTE: this is the symmetric-key ratchet only (no periodic DH
 * ratchet step for post-compromise healing). Fine for prototyping;
 * flagged in the README as a follow-up for a production version.
 */

const crypto = require('crypto');

function chainStep(chainKey) {
  const nextChainKey = Buffer.from(
    crypto.hkdfSync('sha256', chainKey, Buffer.alloc(32, 0), Buffer.from('chain-key'), 32)
  );
  const messageKey = Buffer.from(
    crypto.hkdfSync('sha256', chainKey, Buffer.alloc(32, 0), Buffer.from('message-key'), 32)
  );
  return { nextChainKey, messageKey };
}

class Ratchet {
  constructor(sharedSecret) {
    this.chainKey = sharedSecret;
    this.messageCount = 0;
    this.skippedKeys = new Map(); // index -> messageKey, for out-of-order arrivals
  }

  encrypt(plaintext, associatedData = Buffer.alloc(0)) {
    const { nextChainKey, messageKey } = chainStep(this.chainKey);
    this.chainKey = nextChainKey; // old key is gone — forward secrecy
    const index = this.messageCount++;

    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', messageKey, nonce);
    cipher.setAAD(associatedData);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    return { index, nonce, ciphertext, authTag };
  }

  decrypt(packet, associatedData = Buffer.alloc(0)) {
    const { index, nonce, ciphertext, authTag } = packet;
    let messageKey;

    if (this.skippedKeys.has(index)) {
      messageKey = this.skippedKeys.get(index);
      this.skippedKeys.delete(index);
    } else {
      // advance the chain until we reach this message's index,
      // stashing skipped keys for messages that arrive later
      while (this.messageCount <= index) {
        const { nextChainKey, messageKey: mk } = chainStep(this.chainKey);
        this.chainKey = nextChainKey;
        this.skippedKeys.set(this.messageCount, mk);
        this.messageCount++;
      }
      messageKey = this.skippedKeys.get(index);
      this.skippedKeys.delete(index);
    }

    const decipher = crypto.createDecipheriv('aes-256-gcm', messageKey, nonce);
    decipher.setAAD(associatedData);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }
}

module.exports = { Ratchet };

if (require.main === module) {
  const sharedSecret = crypto.randomBytes(32); // in real use: output of handshake.js

  const aliceRatchet = new Ratchet(sharedSecret);
  const bobRatchet = new Ratchet(sharedSecret);

  const messages = ['hey', 'is this thing secure?', 'cool, testing forward secrecy'];
  const packets = messages.map((m) => aliceRatchet.encrypt(Buffer.from(m, 'utf8')));

  console.log('Decrypting out of order (index 2 first):');
  console.log(' ', bobRatchet.decrypt(packets[2]).toString('utf8'));
  console.log(' ', bobRatchet.decrypt(packets[0]).toString('utf8'));
  console.log(' ', bobRatchet.decrypt(packets[1]).toString('utf8'));
}
