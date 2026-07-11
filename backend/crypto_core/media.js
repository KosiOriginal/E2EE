'use strict';
/**
 * media.js — Encrypted media transfer (images, voice notes).
 *
 * Splits a file into small encrypted+authenticated chunks (needed
 * for relay across a mesh, where a single hop can't carry a whole
 * photo), and verifies the reassembled file wasn't tampered with by
 * any relay node along the way.
 */

const crypto = require('crypto');

const CHUNK_SIZE = 4096; // tune down further for raw BLE transport

function prepareMedia(fileBuffer, mediaType, ratchet) {
  const mediaId = crypto.createHash('sha256').update(fileBuffer).digest('hex').slice(0, 16);
  const chunks = [];

  for (let i = 0; i < fileBuffer.length; i += CHUNK_SIZE) {
    const rawChunk = fileBuffer.subarray(i, i + CHUNK_SIZE);
    const aad = Buffer.from(`${mediaId}:${mediaType}`);
    chunks.push(ratchet.encrypt(rawChunk, aad));
  }

  return { mediaId, totalChunks: chunks.length, mediaType, chunks };
}

function reassembleMedia(envelope, ratchet) {
  const aad = Buffer.from(`${envelope.mediaId}:${envelope.mediaType}`);
  const pieces = envelope.chunks.map((packet) => ratchet.decrypt(packet, aad));
  const result = Buffer.concat(pieces);

  const check = crypto.createHash('sha256').update(result).digest('hex').slice(0, 16);
  if (check !== envelope.mediaId) {
    throw new Error('Media integrity check failed — file corrupted or tampered with');
  }

  return result;
}

module.exports = { prepareMedia, reassembleMedia, CHUNK_SIZE };

if (require.main === module) {
  const { Ratchet } = require('./ratchet');

  const sharedSecret = crypto.randomBytes(32);
  const senderRatchet = new Ratchet(sharedSecret);
  const receiverRatchet = new Ratchet(sharedSecret);

  const fakeVoiceNote = crypto.randomBytes(15000); // pretend it's an .ogg clip

  const envelope = prepareMedia(fakeVoiceNote, 'voice', senderRatchet);
  console.log(`Voice note split into ${envelope.totalChunks} encrypted chunks for mesh relay`);

  const recovered = reassembleMedia(envelope, receiverRatchet);
  console.log('Reassembled correctly:', recovered.equals(fakeVoiceNote));

  // simulate a malicious relay node tampering with a chunk
  const tampered = { ...envelope.chunks[0], ciphertext: Buffer.alloc(envelope.chunks[0].ciphertext.length) };
  envelope.chunks[0] = tampered;
  try {
    reassembleMedia(envelope, new Ratchet(sharedSecret));
  } catch (e) {
    console.log('Tampering correctly detected:', e.message);
  }
}
