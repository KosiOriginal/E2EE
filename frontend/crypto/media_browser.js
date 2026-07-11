'use strict';
/**
 * media_browser.js — chunk + encrypt files (images, voice notes) for
 * sending over the relay, and reassemble + verify on the other end.
 */

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

const CHUNK_SIZE = 16000; // comfortable size for WebSocket text-frame relay

async function prepareMedia(fileBytes, mediaType, ratchet) {
  const mediaId = await sha256Hex(fileBytes);
  const chunks = [];

  for (let i = 0; i < fileBytes.length; i += CHUNK_SIZE) {
    const raw = fileBytes.slice(i, i + CHUNK_SIZE);
    const aad = new TextEncoder().encode(`${mediaId}:${mediaType}`);
    chunks.push(await ratchet.encrypt(raw, aad));
  }

  return { mediaId, totalChunks: chunks.length, mediaType, chunks };
}

async function reassembleMedia(envelope, ratchet) {
  const aad = new TextEncoder().encode(`${envelope.mediaId}:${envelope.mediaType}`);
  const pieces = [];
  for (const packet of envelope.chunks) pieces.push(await ratchet.decrypt(packet, aad));

  const total = pieces.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const p of pieces) {
    result.set(p, offset);
    offset += p.length;
  }

  const check = await sha256Hex(result);
  if (check !== envelope.mediaId) throw new Error('Media integrity check failed — file corrupted or tampered with');

  return result;
}

window.SecnetMedia = { prepareMedia, reassembleMedia };
