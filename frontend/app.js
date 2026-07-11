'use strict';
/**
 * app.js — chat application logic, multi-contact version.
 *
 * Each contact has:
 *  - a name you gave them
 *  - their public key (fixed — this is their permanent identity)
 *  - a ratchet whose state is saved to localStorage after every
 *    single message, so reloading the page does NOT desync you
 *    from your friend anymore
 *  - message history, also saved locally
 */

let myIdentity;
let myFingerprint;
let ws;
let activeFingerprint = null; // which contact's conversation is open
let activeRatchet = null;

const el = (id) => document.getElementById(id);

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

// ---- Rendering ----

function renderContactList() {
  const list = el('contactList');
  list.innerHTML = '';
  const contacts = SecnetContacts.listContacts();

  for (const c of contacts) {
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
    img.src = m.content; // object URL
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

  activeRatchet = contact.ratchetState
    ? SecnetRatchet.RatchetBrowser.fromJSON(contact.ratchetState)
    : null;

  renderChatLog(contact.messages);
  renderContactList();
}

function saveActiveRatchetState() {
  if (!activeFingerprint || !activeRatchet) return;
  SecnetContacts.updateRatchetState(activeFingerprint, activeRatchet.toJSON());
}

async function addContactFlow() {
  const name = el('newContactName').value.trim();
  const keyB64 = el('newContactKey').value.trim();
  if (!name || !keyB64) return;

  const publicKeyBytes = SecnetIdentity.fromB64(keyB64);
  const fingerprint = SecnetIdentity.fingerprint(publicKeyBytes);

  SecnetContacts.addContact(fingerprint, name, keyB64);

  // Establish the shared secret now and save it as the starting ratchet state
  const sharedSecret = await SecnetIdentity.deriveSharedSecret(myIdentity.secretKey, publicKeyBytes);
  const ratchet = new SecnetRatchet.RatchetBrowser(sharedSecret);
  SecnetContacts.updateRatchetState(fingerprint, ratchet.toJSON());

  el('newContactName').value = '';
  el('newContactKey').value = '';
  renderContactList();
  openContact(fingerprint);
}

// ---- Networking ----

let reconnectAttempts = 0;
let heartbeatInterval = null;

function connectWebSocket() {
  const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${protocol}://${location.host}`);

  ws.onopen = () => {
    reconnectAttempts = 0;
    ws.send(JSON.stringify({ type: 'register', fingerprint: myFingerprint }));
    el('status').textContent = 'Connected to relay';

    // Send a small ping periodically. Hosting platforms (Render and
    // most others) close WebSocket connections after ~30-60s of no
    // traffic — without this, the connection silently dies and you'd
    // have to refresh the page to get a new one.
    clearInterval(heartbeatInterval);
    heartbeatInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, 20000);
  };

  ws.onclose = () => {
    clearInterval(heartbeatInterval);
    el('status').textContent = 'Disconnected — reconnecting...';
    // Auto-reconnect with backoff instead of requiring a manual refresh.
    reconnectAttempts++;
    const delay = Math.min(1000 * reconnectAttempts, 8000);
    setTimeout(connectWebSocket, delay);
  };

  ws.onerror = () => {
    ws.close(); // triggers onclose -> reconnect logic above
  };

  attachMessageHandler();
}

async function init() {
  myIdentity = SecnetIdentity.loadOrCreateIdentity();
  myFingerprint = SecnetIdentity.fingerprint(myIdentity.publicKey);
  el('myFingerprint').textContent = myFingerprint;
  el('myPublicKey').textContent = SecnetIdentity.toB64(myIdentity.publicKey);

  renderContactList();
  connectWebSocket();
}

function attachMessageHandler() {

  // Incoming messages must be processed ONE AT A TIME, in order.
  // If two messages arrive close together, the browser would otherwise
  // start handling both concurrently — each loading the same saved
  // ratchet state before the other has saved its update, corrupting
  // the conversation state. This chain forces each message to fully
  // finish (decrypt + save) before the next one starts.
  let processingQueue = Promise.resolve();

  ws.onmessage = (event) => {
    processingQueue = processingQueue.then(() => handleIncoming(event)).catch((err) => {
      console.error('Failed to process incoming message:', err);
    });
  };

  async function handleIncoming(event) {
    const msg = JSON.parse(event.data);
    if (msg.type !== 'relay') return;

    const fromFingerprint = msg.from;
    const contact = SecnetContacts.getContact(fromFingerprint);
    if (!contact) return; // message from someone not in your contacts — ignored

    // Load that contact's ratchet (may not be the currently open conversation)
    const ratchet = contact.ratchetState
      ? SecnetRatchet.RatchetBrowser.fromJSON(contact.ratchetState)
      : null;
    if (!ratchet) return;

    const payload = msg.packet;

    if (payload.kind === 'text') {
      const packet = packetFromJSON(payload.packet);
      const plaintext = await ratchet.decrypt(packet);
      SecnetContacts.updateRatchetState(fromFingerprint, ratchet.toJSON());
      addAndRenderMessage(fromFingerprint, { who: 'friend', kind: 'text', content: new TextDecoder().decode(plaintext), ts: Date.now() });
      if (fromFingerprint === activeFingerprint) activeRatchet = ratchet; // keep in-memory copy in sync
    }

    if (payload.kind === 'media') {
      const envelope = {
        mediaId: payload.mediaId,
        mediaType: payload.mediaType,
        totalChunks: payload.chunks.length,
        chunks: payload.chunks.map(packetFromJSON),
      };
      const fileBytes = await SecnetMedia.reassembleMedia(envelope, ratchet);
      SecnetContacts.updateRatchetState(fromFingerprint, ratchet.toJSON());
      const blob = new Blob([fileBytes], { type: payload.mediaType === 'image' ? 'image/png' : 'audio/webm' });
      const url = URL.createObjectURL(blob);
      addAndRenderMessage(fromFingerprint, { who: 'friend', kind: payload.mediaType, content: url, ts: Date.now() });
      if (fromFingerprint === activeFingerprint) activeRatchet = ratchet;
    }
  };
}

async function sendText() {
  const text = el('messageInput').value;
  if (!text || !activeRatchet || !activeFingerprint) return;

  const packet = await activeRatchet.encrypt(new TextEncoder().encode(text));
  saveActiveRatchetState();

  ws.send(JSON.stringify({
    type: 'relay',
    to: activeFingerprint,
    packet: { kind: 'text', packet: packetToJSON(packet) },
  }));

  addAndRenderMessage(activeFingerprint, { who: 'me', kind: 'text', content: text, ts: Date.now() });
  el('messageInput').value = '';
}

async function sendFile(file, mediaType) {
  if (!activeRatchet || !activeFingerprint) return;
  const bytes = new Uint8Array(await file.arrayBuffer());
  const envelope = await SecnetMedia.prepareMedia(bytes, mediaType, activeRatchet);
  saveActiveRatchetState();

  ws.send(JSON.stringify({
    type: 'relay',
    to: activeFingerprint,
    packet: {
      kind: 'media',
      mediaId: envelope.mediaId,
      mediaType: envelope.mediaType,
      chunks: envelope.chunks.map(packetToJSON),
    },
  }));

  const url = URL.createObjectURL(file);
  addAndRenderMessage(activeFingerprint, { who: 'me', kind: mediaType, content: url, ts: Date.now() });
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

  el('addContactBtn').addEventListener('click', addContactFlow);
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
