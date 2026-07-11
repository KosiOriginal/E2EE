'use strict';
/**
 * app.js — chat application logic.
 *
 * Flow:
 *  1. Generate/load my identity on page load, show my fingerprint.
 *  2. Connect to the relay server over WebSocket, register my fingerprint.
 *  3. Paste in a friend's public key (they get it by sharing their own
 *     fingerprint/key with you out-of-band — text it, say it in person, etc).
 *  4. That derives a shared secret -> seeds a ratchet -> every message
 *     after that gets its own encryption key.
 *  5. Send text, images, or voice notes — all encrypted client-side
 *     before they ever touch the network.
 */

let myIdentity;
let myFingerprint;
let ws;
let friendPublicKey = null;
let friendFingerprint = null;
let ratchet = null; // one active conversation at a time in this version

const el = (id) => document.getElementById(id);

function appendMessage(who, text) {
  const div = document.createElement('div');
  div.className = `msg ${who}`;
  div.textContent = `${who === 'me' ? 'You' : 'Friend'}: ${text}`;
  el('chatLog').appendChild(div);
  el('chatLog').scrollTop = el('chatLog').scrollHeight;
}

function appendImage(who, blobUrl) {
  const wrapper = document.createElement('div');
  wrapper.className = `msg ${who}`;
  const label = document.createElement('div');
  label.textContent = who === 'me' ? 'You sent an image:' : 'Friend sent an image:';
  const img = document.createElement('img');
  img.src = blobUrl;
  img.style.maxWidth = '240px';
  img.style.display = 'block';
  wrapper.appendChild(label);
  wrapper.appendChild(img);
  el('chatLog').appendChild(wrapper);
  el('chatLog').scrollTop = el('chatLog').scrollHeight;
}

function appendAudio(who, blobUrl) {
  const wrapper = document.createElement('div');
  wrapper.className = `msg ${who}`;
  const label = document.createElement('div');
  label.textContent = who === 'me' ? 'You sent a voice note:' : 'Friend sent a voice note:';
  const audio = document.createElement('audio');
  audio.controls = true;
  audio.src = blobUrl;
  wrapper.appendChild(label);
  wrapper.appendChild(audio);
  el('chatLog').appendChild(wrapper);
  el('chatLog').scrollTop = el('chatLog').scrollHeight;
}

function packetToJSON(packet) {
  return {
    index: packet.index,
    nonce: SecnetIdentity.toB64(packet.nonce),
    ciphertext: SecnetIdentity.toB64(packet.ciphertext),
  };
}
function packetFromJSON(obj) {
  return {
    index: obj.index,
    nonce: SecnetIdentity.fromB64(obj.nonce),
    ciphertext: SecnetIdentity.fromB64(obj.ciphertext),
  };
}

async function init() {
  myIdentity = SecnetIdentity.loadOrCreateIdentity();
  myFingerprint = SecnetIdentity.fingerprint(myIdentity.publicKey);
  el('myFingerprint').textContent = myFingerprint;
  el('myPublicKey').textContent = SecnetIdentity.toB64(myIdentity.publicKey);

  const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${protocol}://${location.host}`);

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: 'register', fingerprint: myFingerprint }));
    el('status').textContent = 'Connected to relay';
  };

  ws.onclose = () => {
    el('status').textContent = 'Disconnected — refresh to reconnect';
  };

  ws.onmessage = async (event) => {
    const msg = JSON.parse(event.data);
    if (msg.type !== 'relay') return;
    if (!ratchet) return; // no session established yet, drop it

    const payload = msg.packet;

    if (payload.kind === 'text') {
      const packet = packetFromJSON(payload.packet);
      const plaintext = await ratchet.decrypt(packet);
      appendMessage('friend', new TextDecoder().decode(plaintext));
    }

    if (payload.kind === 'media') {
      const envelope = {
        mediaId: payload.mediaId,
        mediaType: payload.mediaType,
        totalChunks: payload.chunks.length,
        chunks: payload.chunks.map(packetFromJSON),
      };
      const fileBytes = await SecnetMedia.reassembleMedia(envelope, ratchet);
      const blob = new Blob([fileBytes], { type: payload.mediaType === 'image' ? 'image/png' : 'audio/webm' });
      const url = URL.createObjectURL(blob);
      if (payload.mediaType === 'image') appendImage('friend', url);
      else appendAudio('friend', url);
    }
  };
}

async function connectToFriend() {
  const pubKeyB64 = el('friendKeyInput').value.trim();
  if (!pubKeyB64) return;

  friendPublicKey = SecnetIdentity.fromB64(pubKeyB64);
  friendFingerprint = SecnetIdentity.fingerprint(friendPublicKey);

  const sharedSecret = await SecnetIdentity.deriveSharedSecret(myIdentity.secretKey, friendPublicKey);
  ratchet = new SecnetRatchet.RatchetBrowser(sharedSecret);

  el('friendFingerprint').textContent = friendFingerprint;
  el('status').textContent = `Session established — verify this fingerprint matches your friend's out loud: ${friendFingerprint}`;
  appendMessage('me', '[session started]');
}

async function sendText() {
  const text = el('messageInput').value;
  if (!text || !ratchet || !friendFingerprint) return;

  const packet = await ratchet.encrypt(new TextEncoder().encode(text));
  ws.send(JSON.stringify({
    type: 'relay',
    to: friendFingerprint,
    packet: { kind: 'text', packet: packetToJSON(packet) },
  }));

  appendMessage('me', text);
  el('messageInput').value = '';
}

async function sendFile(file, mediaType) {
  if (!ratchet || !friendFingerprint) return;
  const bytes = new Uint8Array(await file.arrayBuffer());
  const envelope = await SecnetMedia.prepareMedia(bytes, mediaType, ratchet);

  ws.send(JSON.stringify({
    type: 'relay',
    to: friendFingerprint,
    packet: {
      kind: 'media',
      mediaId: envelope.mediaId,
      mediaType: envelope.mediaType,
      chunks: envelope.chunks.map(packetToJSON),
    },
  }));

  const url = URL.createObjectURL(file);
  if (mediaType === 'image') appendImage('me', url);
  else appendAudio('me', url);
}

// ---- Voice recording ----
let mediaRecorder = null;
let recordedChunks = [];

async function startRecording() {
  const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
  mediaRecorder = new MediaRecorder(stream);
  recordedChunks = [];
  mediaRecorder.ondataavailable = (e) => recordedChunks.push(e.data);
  mediaRecorder.onstop = async () => {
    const blob = new Blob(recordedChunks, { type: 'audio/webm' });
    const file = new File([blob], 'voice-note.webm', { type: 'audio/webm' });
    await sendFile(file, 'voice');
  };
  mediaRecorder.start();
  el('recordBtn').textContent = 'Stop recording';
}

function stopRecording() {
  if (mediaRecorder) mediaRecorder.stop();
  el('recordBtn').textContent = 'Record voice note';
}

window.addEventListener('DOMContentLoaded', () => {
  init();

  el('connectBtn').addEventListener('click', connectToFriend);
  el('sendBtn').addEventListener('click', sendText);
  el('messageInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') sendText();
  });

  el('imageInput').addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) sendFile(file, 'image');
    e.target.value = '';
  });

  let recording = false;
  el('recordBtn').addEventListener('click', () => {
    recording = !recording;
    if (recording) startRecording();
    else stopRecording();
  });
});
