'use strict';
/**
 * app.js — chat application logic, multi-contact version.
 *
 * Key properties:
 *  - One shared in-memory ratchet per contact + a single serialization
 *    queue for all encrypt/decrypt ops, so sending and receiving can
 *    never race and corrupt each other's state.
 *  - Media (images/voice) is sent as SEPARATE small WebSocket messages,
 *    one per chunk — NOT bundled into one giant message. Many hosting
 *    proxies (including Render) cap individual WebSocket message size;
 *    a multi-MB photo sent as one message can silently fail or destabilize
 *    the connection. Sending chunk-by-chunk avoids that entirely.
 *  - Errors surface directly in the chat UI, not just the console —
 *    console errors are useless when testing on a phone.
 */

let myIdentity;
let myFingerprint;
let ws;
let activeFingerprint = null;

const el = (id) => document.getElementById(id);

// ---- Single source of truth for ratchet state, one per contact ----

const ratchetCache = new Map();

function getRatchet(fingerprint) {
  if (ratchetCache.has(fingerprint)) return ratchetCache.get(fingerprint);
  const contact = SecnetContacts.getContact(fingerprint);
  if (!contact || !contact.ratchetState) return null;
  const ratchet = SecnetRatchet.RatchetBrowser.fromJSON(contact.ratchetState);
  ratchetCache.set(fingerprint, ratchet);
  return ratchet;
}

function persistRatchet(fingerprint) {
  const ratchet = ratchetCache.get(fingerprint);
  if (!ratchet) return;
  SecnetContacts.updateRatchetState(fingerprint, ratchet.toJSON());
}

let opQueue = Promise.resolve();
function enqueue(fn) {
  const result = opQueue.then(fn, fn);
  opQueue = result.catch(() => {});
  return result;
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

// Browser-native, robust encode/decode — avoids manual base64 chunking
// edge cases on some mobile browsers.
function blobToDataURL(blob) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(reader.error || new Error('FileReader failed'));
    reader.readAsDataURL(blob);
  });
}

function showError(message) {
  console.error(message);
  const status = el('status');
  status.textContent = `⚠️ ${message}`;
  status.style.color = '#f66';
  setTimeout(() => {
    status.style.color = '';
    status.textContent = ws && ws.readyState === WebSocket.OPEN ? 'Connected to relay' : 'Disconnected — reconnecting...';
  }, 4000);
}

// ---- Rendering ----

function renderContactList() {
  const list = el('contactList');
  list.innerHTML = '';
  for (const c of SecnetContacts.listContacts()) {
    const item = document.createElement('div');
    item.className = 'contact-item' + (c.fingerprint === activeFingerprint ? ' active' : '');
    item.textContent = c.name;
    item.addEventListener('click', () => openContact(c.fingerprint));
    list.appendChild(item);
  }
}

function renderChatLog(messages) {
  const chatLog = el('chatLog');
  chatLog.innerHTML = '';
  for (const m of messages) renderOneMessage(m);
  chatLog.scrollTop = chatLog.scrollHeight;
}

function renderOneMessage(m) {
  const chatLog = el('chatLog');
  const wrapper = document.createElement('div');
  wrapper.className = `msg ${m.who}`;

  if (m.kind === 'text') {
    wrapper.textContent = `${m.who === 'me' ? 'You' : 'Friend'}: ${m.content}`;
  } else if (m.kind === 'image') {
    const label = document.createElement('div');
    label.textContent = m.who === 'me' ? 'You sent an image:' : 'Friend sent an image:';
    const img = document.createElement('img');
    img.src = m.content;
    img.style.maxWidth = '240px';
    img.style.display = 'block';
    wrapper.appendChild(label);
    wrapper.appendChild(img);
  } else if (m.kind === 'voice') {
    const label = document.createElement('div');
    label.textContent = m.who === 'me' ? 'You sent a voice note:' : 'Friend sent a voice note:';
    const audio = document.createElement('audio');
    audio.controls = true;
    audio.src = m.content;
    wrapper.appendChild(label);
    wrapper.appendChild(audio);
  }

  chatLog.appendChild(wrapper);
}

function addAndRenderMessage(fingerprint, message) {
  SecnetContacts.appendMessageToHistory(fingerprint, message);
  if (fingerprint === activeFingerprint) {
    renderOneMessage(message);
    el('chatLog').scrollTop = el('chatLog').scrollHeight;
  }
}

// ---- Conversation management ----

function openContact(fingerprint) {
  activeFingerprint = fingerprint;
  const contact = SecnetContacts.getContact(fingerprint);
  if (!contact) return;

  el('activeContactName').textContent = contact.name;
  el('activeContactFingerprint').textContent = fingerprint;
  el('chatPanel').style.display = 'block';
  document.body.classList.add('chat-open'); // mobile: switch from contact list to chat screen

  renderChatLog(contact.messages);
  renderContactList();
}

function closeChat() {
  document.body.classList.remove('chat-open'); // mobile: back to contact list
}

async function addContactFlow() {
  const name = el('newContactName').value.trim();
  const keyB64 = el('newContactKey').value.trim();
  if (!name || !keyB64) return;

  try {
    const publicKeyBytes = SecnetIdentity.fromB64(keyB64);
    const fingerprint = SecnetIdentity.fingerprint(publicKeyBytes);

    SecnetContacts.addContact(fingerprint, name, keyB64);

    const sharedSecret = await SecnetIdentity.deriveSharedSecret(myIdentity.secretKey, publicKeyBytes);
    const ratchet = new SecnetRatchet.RatchetBrowser(sharedSecret);
    ratchetCache.set(fingerprint, ratchet);
    persistRatchet(fingerprint);

    el('newContactName').value = '';
    el('newContactKey').value = '';
    renderContactList();
    openContact(fingerprint);
  } catch (err) {
    showError('Could not add contact — check the public key was pasted correctly.');
  }
}

// ---- Networking ----

let reconnectAttempts = 0;
let heartbeatInterval = null;

// Incoming media chunks accumulate here, keyed by mediaId, until all
// chunks for that file have arrived — then we reassemble.
const incomingMediaBuffers = new Map();

function connectWebSocket() {
  const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${protocol}://${location.host}`);

  ws.onopen = () => {
    reconnectAttempts = 0;
    ws.send(JSON.stringify({ type: 'register', fingerprint: myFingerprint }));
    el('status').textContent = 'Connected to relay';
    el('status').style.color = '';

    clearInterval(heartbeatInterval);
    heartbeatInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping' }));
    }, 20000);
  };

  ws.onclose = () => {
    clearInterval(heartbeatInterval);
    el('status').textContent = 'Disconnected — reconnecting...';
    reconnectAttempts++;
    setTimeout(connectWebSocket, Math.min(1000 * reconnectAttempts, 8000));
  };

  ws.onerror = () => ws.close();

  ws.onmessage = (event) => {
    enqueue(() => handleIncoming(event)).catch((err) => {
      showError('Incoming message error: ' + (err && err.message ? err.message : String(err)));
    });
  };
}

async function handleIncoming(event) {
  const msg = JSON.parse(event.data);
  if (msg.type !== 'relay') return;

  const fromFingerprint = msg.from;
  const contact = SecnetContacts.getContact(fromFingerprint);
  if (!contact) return;

  const ratchet = getRatchet(fromFingerprint);
  if (!ratchet) return;

  const payload = msg.packet;

  if (payload.kind === 'text') {
    const packet = packetFromJSON(payload.packet);
    const plaintext = await ratchet.decrypt(packet);
    persistRatchet(fromFingerprint);
    addAndRenderMessage(fromFingerprint, {
      who: 'friend', kind: 'text', content: new TextDecoder().decode(plaintext), ts: Date.now(),
    });
    return;
  }

  if (payload.kind === 'media_chunk') {
    const { mediaId, mediaType, chunkIndex, totalChunks } = payload;

    if (!incomingMediaBuffers.has(mediaId)) {
      incomingMediaBuffers.set(mediaId, { mediaType, totalChunks, fromFingerprint, chunks: new Map() });
    }
    const buffer = incomingMediaBuffers.get(mediaId);
    const packet = packetFromJSON(payload.packet);
    const plaintextChunk = await ratchet.decrypt(packet, new TextEncoder().encode(`${mediaId}:${mediaType}`));
    persistRatchet(fromFingerprint);
    buffer.chunks.set(chunkIndex, plaintextChunk);

    if (buffer.chunks.size === buffer.totalChunks) {
      const ordered = [];
      for (let i = 0; i < buffer.totalChunks; i++) ordered.push(buffer.chunks.get(i));
      const total = ordered.reduce((sum, c) => sum + c.length, 0);
      const fileBytes = new Uint8Array(total);
      let offset = 0;
      for (const c of ordered) {
        fileBytes.set(c, offset);
        offset += c.length;
      }
      incomingMediaBuffers.delete(mediaId);

      const mimeType = mediaType === 'image' ? 'image/png' : 'audio/webm';
      const blob = new Blob([fileBytes], { type: mimeType });
      const url = await blobToDataURL(blob);
      addAndRenderMessage(fromFingerprint, { who: 'friend', kind: mediaType, content: url, ts: Date.now() });
    }
  }
}

async function init() {
  myIdentity = SecnetIdentity.loadOrCreateIdentity();
  myFingerprint = SecnetIdentity.fingerprint(myIdentity.publicKey);
  el('myFingerprint').textContent = myFingerprint;
  el('myPublicKey').textContent = SecnetIdentity.toB64(myIdentity.publicKey);

  renderContactList();
  connectWebSocket();
}

async function sendText() {
  const text = el('messageInput').value;
  if (!text || !activeFingerprint) return;
  const fingerprint = activeFingerprint;
  el('messageInput').value = '';

  try {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error('Not connected to the server right now — wait for reconnect and try again.');
    }

    await enqueue(async () => {
      const ratchet = getRatchet(fingerprint);
      if (!ratchet) throw new Error('No secure session with this contact yet.');

      const packet = await ratchet.encrypt(new TextEncoder().encode(text));
      persistRatchet(fingerprint);

      ws.send(JSON.stringify({
        type: 'relay',
        to: fingerprint,
        packet: { kind: 'text', packet: packetToJSON(packet) },
      }));

      addAndRenderMessage(fingerprint, { who: 'me', kind: 'text', content: text, ts: Date.now() });
    });
  } catch (err) {
    showError('Message failed to send: ' + err.message);
  }
}

async function sendFile(file, mediaType) {
  if (!activeFingerprint) return;
  const fingerprint = activeFingerprint;

  try {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      throw new Error('Not connected to the server right now — wait for reconnect and try again.');
    }

    const bytes = new Uint8Array(await file.arrayBuffer());

    await enqueue(async () => {
      const ratchet = getRatchet(fingerprint);
      if (!ratchet) throw new Error('No secure session with this contact yet.');

      const CHUNK_SIZE = 8000;
      const mediaId = await sha256Hex(bytes);
      const totalChunks = Math.ceil(bytes.length / CHUNK_SIZE) || 1;

      // Each chunk is its OWN WebSocket message, not bundled — avoids
      // proxy message-size limits and connection instability on
      // larger files.
      for (let i = 0; i < totalChunks; i++) {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
          throw new Error(`Connection dropped mid-transfer (chunk ${i + 1}/${totalChunks}) — try sending again.`);
        }

        const raw = bytes.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
        const aad = new TextEncoder().encode(`${mediaId}:${mediaType}`);
        const packet = await ratchet.encrypt(raw, aad);
        persistRatchet(fingerprint);

        ws.send(JSON.stringify({
          type: 'relay',
          to: fingerprint,
          packet: {
            kind: 'media_chunk',
            mediaId,
            mediaType,
            chunkIndex: i,
            totalChunks,
            packet: packetToJSON(packet),
          },
        }));
      }

      const url = await blobToDataURL(file);
      addAndRenderMessage(fingerprint, { who: 'me', kind: mediaType, content: url, ts: Date.now() });
    });
  } catch (err) {
    showError('File failed to send: ' + err.message);
  }
}

async function sha256Hex(bytes) {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
}

// ---- Voice recording ----
let mediaRecorder = null;
let recordedChunks = [];

async function startRecording() {
  try {
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
  } catch (err) {
    showError('Could not access microphone: ' + err.message);
  }
}
function stopRecording() {
  if (mediaRecorder) mediaRecorder.stop();
  el('recordBtn').textContent = 'Record voice note';
}

window.addEventListener('DOMContentLoaded', () => {
  init();

  el('addContactBtn').addEventListener('click', addContactFlow);
  el('backBtn').addEventListener('click', closeChat);
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
