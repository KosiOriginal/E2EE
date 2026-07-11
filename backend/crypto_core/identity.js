'use strict';
/**
 * identity.js — Device identity.
 *
 * Identity = a keypair, nothing else. No phone number, no email,
 * no account with a company. Generated once, private key never
 * leaves the device.
 */

const crypto = require('crypto');

function generateIdentity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  return { publicKey, privateKey };
}

function publicKeyToRaw(publicKeyObj) {
  // raw 32-byte public key, the thing you actually send to friends
  return publicKeyObj.export({ type: 'spki', format: 'der' }).subarray(-32);
}

function rawToPublicKey(rawBytes) {
  // Node needs the key wrapped back in DER/SPKI to reconstruct a KeyObject
  const prefix = Buffer.from('302a300506032b656e032100', 'hex');
  const der = Buffer.concat([prefix, rawBytes]);
  return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
}

function fingerprint(publicKeyObj) {
  // Human-verifiable ID — read this aloud to a friend once, in person
  // or over a trusted channel, to rule out man-in-the-middle attacks.
  const raw = publicKeyToRaw(publicKeyObj);
  const b32 = raw.toString('base64').replace(/[+/=]/g, '').toUpperCase();
  return b32.match(/.{1,4}/g).join('-');
}

// A batch of one-time "prekeys" published so others can start a
// session with you even while you're offline (see handshake.js).
function generatePrekeyBundle(identity, count = 20) {
  const signedPrekey = generateIdentity();
  const oneTimePrekeys = Array.from({ length: count }, () => generateIdentity());

  return {
    identityPub: publicKeyToRaw(identity.publicKey),
    signedPrekeyPriv: signedPrekey.privateKey,
    signedPrekeyPub: publicKeyToRaw(signedPrekey.publicKey),
    oneTimePrekeys, // keep full objects locally (has private halves)
    oneTimePrekeysPub: oneTimePrekeys.map((k) => publicKeyToRaw(k.publicKey)),
  };
}

module.exports = {
  generateIdentity,
  publicKeyToRaw,
  rawToPublicKey,
  fingerprint,
  generatePrekeyBundle,
};

if (require.main === module) {
  const me = generateIdentity();
  console.log('Generated identity.');
  console.log('Fingerprint (verify with a friend in person or via a trusted channel):');
  console.log(' ', fingerprint(me.publicKey));
}
