'use strict';
/**
 * handshake.js — X3DH-style key agreement.
 *
 * Lets two people derive the SAME shared secret without ever being
 * online at the same time — one publishes prekeys in advance, the
 * other picks them up later and computes independently.
 */

const crypto = require('crypto');
const { rawToPublicKey, publicKeyToRaw } = require('./identity');

function dh(privateKeyObj, otherPublicRaw) {
  const otherPub = rawToPublicKey(otherPublicRaw);
  return crypto.diffieHellman({ privateKey: privateKeyObj, publicKey: otherPub });
}

function kdf(...buffers) {
  const ikm = Buffer.concat(buffers);
  // HKDF-SHA256, 32-byte output
  return Buffer.from(
    crypto.hkdfSync('sha256', ikm, Buffer.alloc(32, 0), Buffer.from('secnet-x3dh'), 32)
  );
}

/**
 * Run by whoever STARTS the conversation.
 * `responderBundlePublic` = { identityPub, signedPrekeyPub, oneTimePrekeysPub[] }
 * (only public bytes — this is what the responder published while offline)
 */
function initiateSession(myIdentity, responderBundlePublic) {
  const ephemeral = crypto.generateKeyPairSync('x25519');

  const ikA = myIdentity.privateKey;
  const ikBPub = responderBundlePublic.identityPub;
  const spkBPub = responderBundlePublic.signedPrekeyPub;
  const opkBPub = responderBundlePublic.oneTimePrekeysPub[0]; // pick first available

  const dh1 = dh(ikA, spkBPub);
  const dh2 = dh(ephemeral.privateKey, ikBPub);
  const dh3 = dh(ephemeral.privateKey, spkBPub);
  const dh4 = opkBPub ? dh(ephemeral.privateKey, opkBPub) : Buffer.alloc(0);

  const sharedSecret = kdf(dh1, dh2, dh3, dh4);
  return { sharedSecret, ephemeralPub: publicKeyToRaw(ephemeral.publicKey) };
}

/**
 * Run by whoever PUBLISHED the bundle, once they come online and see
 * the initiator's first message + ephemeral key.
 */
function respondSession(myIdentity, myBundle, initiatorIdentityPub, initiatorEphemeralPub, usedOneTimePrekeyPriv) {
  const ikB = myIdentity.privateKey;
  const spkB = myBundle.signedPrekeyPriv;

  const dh1 = dh(spkB, initiatorIdentityPub);
  const dh2 = dh(ikB, initiatorEphemeralPub);
  const dh3 = dh(spkB, initiatorEphemeralPub);
  const dh4 = usedOneTimePrekeyPriv ? dh(usedOneTimePrekeyPriv, initiatorEphemeralPub) : Buffer.alloc(0);

  return kdf(dh1, dh2, dh3, dh4);
}

module.exports = { initiateSession, respondSession };

if (require.main === module) {
  const { generateIdentity, generatePrekeyBundle, publicKeyToRaw } = require('./identity');

  // Bob publishes a bundle, then goes offline
  const bobIdentity = generateIdentity();
  const bobBundle = generatePrekeyBundle(bobIdentity, 5);
  const bobBundlePublic = {
    identityPub: publicKeyToRaw(bobIdentity.publicKey),
    signedPrekeyPub: bobBundle.signedPrekeyPub,
    oneTimePrekeysPub: bobBundle.oneTimePrekeysPub,
  };

  // Alice comes online, starts session using only Bob's public bundle
  const aliceIdentity = generateIdentity();
  const { sharedSecret: aliceSecret, ephemeralPub } = initiateSession(aliceIdentity, bobBundlePublic);

  // Bob comes back online, completes handshake
  const usedPrekey = bobBundle.oneTimePrekeys[0]; // matches oneTimePrekeysPub[0] used above
  const bobSecret = respondSession(
    bobIdentity,
    bobBundle,
    publicKeyToRaw(aliceIdentity.publicKey),
    ephemeralPub,
    usedPrekey.privateKey
  );

  console.log('Alice secret:', aliceSecret.toString('hex'));
  console.log('Bob secret:  ', bobSecret.toString('hex'));
  console.log('Match:', aliceSecret.equals(bobSecret));
}
