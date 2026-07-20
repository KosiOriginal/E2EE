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

function setSignalState(state, text) {
  const status = el('status');
  status.dataset.state = state;
  el('statusText').textContent = text;
}

function showError(message) {
  console.error(message);
  const status = el('status');
  const statusText = el('statusText');
  const previousState = status.dataset.state;

  statusText.textContent = message;
  status.classList.add('status-error');

  setTimeout(() => {
    status.classList.remove('status-error');
    if (ws && ws.readyState === WebSocket.OPEN) {
      setSignalState('secure', 'Line secure');
    } else {
      setSignalState(previousState === 'lost' ? 'lost' : 'searching', 'Re-establishing link\u2026');
    }
  }, 4000);
}

// ---- Rendering ----

const unreadCounts = new Map(); // fingerprint -> count, in-memory only

function renderContactList() {
  const list = el('contactList');
  list.innerHTML = '';
  for (const c of SecnetContacts.listContacts()) {
    const item = document.createElement('div');
    item.className = 'contact-item' + (c.fingerprint === activeFingerprint ? ' active' : '');

    const nameSpan = document.createElement('span');
    const unread = unreadCounts.get(c.fingerprint);
    nameSpan.textContent = unread ? `${c.name} (${unread})` : c.name;
    item.appendChild(nameSpan);
    item.addEventListener('click', () => openContact(c.fingerprint));

    const delBtn = document.createElement('button');
    delBtn.textContent = '\u2715';
    delBtn.title = 'Delete contact';
    delBtn.style.marginLeft = '8px';
    delBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      if (!confirm(`Delete ${c.name}? This removes your conversation history and ratchet state.`)) return;
      SecnetContacts.removeContact(c.fingerprint);
      ratchetCache.delete(c.fingerprint);
      unreadCounts.delete(c.fingerprint);
      if (activeFingerprint === c.fingerprint) {
        activeFingerprint = null;
        el('chatPanel').style.display = 'none';
        closeChat();
      }
      renderContactList();
    });
    item.appendChild(delBtn);

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
  } else if (message.who === 'friend') {
    // Chat with this contact isn't open right now — surface a
    // notification instead of the message silently landing unseen.
    unreadCounts.set(fingerprint, (unreadCounts.get(fingerprint) || 0) + 1);
    renderContactList();
    flashTitle();
    const contact = SecnetContacts.getContact(fingerprint);
    if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
      try {
        new Notification('secnet', { body: `New message from ${contact ? contact.name : fingerprint}` });
      } catch {}
    }
  }
}

// ---- Conversation management ----

function openContact(fingerprint) {
  activeFingerprint = fingerprint;
  const contact = SecnetContacts.getContact(fingerprint);
  if (!contact) return;

  el('activeContactName').textContent = contact.name;
  el('activeContactFingerprint').textContent = fingerprint;
  el('chatPanel').style.display = 'flex';
  document.body.classList.add('chat-open'); // mobile: switch from contact list to chat screen
  stopFlashingTitle();
  unreadCounts.delete(fingerprint);

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
    await enqueue(() => replayPendingMessages(fingerprint));
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
    setSignalState('secure', 'Line secure');

    clearInterval(heartbeatInterval);
    heartbeatInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping' }));
    }, 20000);
  };

  ws.onclose = () => {
    clearInterval(heartbeatInterval);
    setSignalState('searching', 'Re-establishing link\u2026');
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

  if (!contact) {
    // We don't have a session with this sender yet. Save the encrypted
    // packet (we can't read it without adding them) and let the user know.
    stashPendingMessage(fromFingerprint, msg.fromPublicKey, msg.packet);
    notifyUnknownSender(fromFingerprint);
    return;
  }

  const ratchet = getRatchet(fromFingerprint);
  if (!ratchet) return;

  await processPayload(fromFingerprint, ratchet, msg.packet);
}

async function processPayload(fromFingerprint, ratchet, payload) {
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
    const { mediaId, mediaType, chunkIndex, totalChunks, mime } = payload;

    if (!incomingMediaBuffers.has(mediaId)) {
      incomingMediaBuffers.set(mediaId, {
        mediaType,
        mime: mime || (mediaType === 'image' ? 'image/jpeg' : 'audio/webm'),
        totalChunks,
        fromFingerprint,
        chunks: new Map(),
      });
    }
    const buffer = incomingMediaBuffers.get(mediaId);
    const packet = packetFromJSON(payload.packet);
    let plaintextChunk;
    try {
      plaintextChunk = await ratchet.decrypt(packet, new TextEncoder().encode(`${mediaId}:${mediaType}`));
    } catch (cryptoErr) {
      incomingMediaBuffers.delete(mediaId);
      throw new Error(`Could not decrypt chunk ${chunkIndex + 1}/${totalChunks} of incoming ${mediaType} — connection likely dropped mid-transfer, ask them to resend.`);
    }
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

      const mimeType = buffer.mime;
      const blob = new Blob([fileBytes], { type: mimeType });
      const url = await blobToDataURL(blob);
      addAndRenderMessage(fromFingerprint, { who: 'friend', kind: mediaType, content: url, ts: Date.now() });
    }
    return;
  }

  if (typeof payload.kind === 'string' && payload.kind.startsWith('call_')) {
    const subkind = payload.kind.slice(5); // 'offer' | 'answer' | 'ice' | 'end'
    const packet = packetFromJSON(payload.packet);
    let plaintext;
    try {
      plaintext = await ratchet.decrypt(packet, callAad(subkind));
    } catch (cryptoErr) {
      console.error('Could not decrypt call signal:', cryptoErr);
      return;
    }
    persistRatchet(fromFingerprint);
    const data = JSON.parse(new TextDecoder().decode(plaintext));

    if (subkind === 'offer') return handleIncomingOffer(fromFingerprint, data);
    if (subkind === 'answer') return handleIncomingAnswer(fromFingerprint, data);
    if (subkind === 'ice') return handleIncomingIce(fromFingerprint, data);
    if (subkind === 'end') return handleIncomingEnd(fromFingerprint);
  }
}

// ---- Unknown senders: messages from people not yet in your contacts ----
// We can't decrypt these (no ratchet exists yet), so we save the raw
// encrypted packets and surface a notification + an "Add contact" prompt.
// Once the contact is added, the stash is replayed and decrypted normally.

const PENDING_KEY = 'secnet_pending_v1';

function loadPending() {
  const raw = localStorage.getItem(PENDING_KEY);
  return raw ? JSON.parse(raw) : {};
}
function savePending(pending) {
  try {
    localStorage.setItem(PENDING_KEY, JSON.stringify(pending));
  } catch (err) {
    console.error('Could not save pending message stash:', err);
  }
}

function stashPendingMessage(fingerprint, fromPublicKey, payload) {
  const pending = loadPending();
  if (!pending[fingerprint]) pending[fingerprint] = { fromPublicKey: null, payloads: [] };
  if (fromPublicKey) pending[fingerprint].fromPublicKey = fromPublicKey;
  pending[fingerprint].payloads.push(payload);
  savePending(pending);
  renderUnknownSenders();
}

function renderUnknownSenders() {
  const pending = loadPending();
  const entries = Object.entries(pending);
  const panel = el('unknownPanel');
  const list = el('unknownList');
  if (!panel || !list) return;

  if (entries.length === 0) {
    panel.style.display = 'none';
    list.innerHTML = '';
    return;
  }

  panel.style.display = 'block';
  list.innerHTML = '';
  for (const [fingerprint, data] of entries) {
    const item = document.createElement('div');
    item.className = 'contact-item';
    item.textContent = `${fingerprint} (${data.payloads.length} msg${data.payloads.length > 1 ? 's' : ''})`;

    const addBtn = document.createElement('button');
    addBtn.textContent = 'Add contact';
    addBtn.style.marginLeft = '8px';
    addBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      el('newContactKey').value = data.fromPublicKey || '';
      el('newContactName').value = '';
      el('newContactName').focus();
    });

    item.appendChild(addBtn);
    list.appendChild(item);
  }
}

async function replayPendingMessages(fingerprint) {
  const pending = loadPending();
  const entry = pending[fingerprint];
  if (!entry) return;

  const ratchet = getRatchet(fingerprint);
  if (!ratchet) return;

  for (const payload of entry.payloads) {
    try {
      await processPayload(fingerprint, ratchet, payload);
    } catch (err) {
      console.error('Could not decrypt a pending message — it may be corrupted:', err);
    }
  }

  delete pending[fingerprint];
  savePending(pending);
  renderUnknownSenders();
}

function notifyUnknownSender(fingerprint) {
  showError(`New message from an unknown contact (${fingerprint}) — add them to read it.`);
  flashTitle();
  if (typeof Notification !== 'undefined' && Notification.permission === 'granted') {
    try {
      new Notification('secnet', { body: `New message from an unknown contact: ${fingerprint}` });
    } catch {}
  }
}

let titleFlashInterval = null;
const ORIGINAL_TITLE = document.title;
function flashTitle() {
  if (titleFlashInterval) return;
  let on = false;
  titleFlashInterval = setInterval(() => {
    document.title = on ? ORIGINAL_TITLE : '🔔 New message!';
    on = !on;
  }, 1000);
}
function stopFlashingTitle() {
  if (titleFlashInterval) {
    clearInterval(titleFlashInterval);
    titleFlashInterval = null;
  }
  document.title = ORIGINAL_TITLE;
}

// ---- Theme (Settings > Theme) ----

const THEME_KEY = 'secnet_theme_v1';

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  try {
    localStorage.setItem(THEME_KEY, theme);
  } catch (err) {
    console.error('Could not save theme choice:', err);
  }
  document.querySelectorAll('.theme-swatch').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.themeOption === theme);
  });
}

function initTheme() {
  let saved = 'field';
  try {
    saved = localStorage.getItem(THEME_KEY) || 'field';
  } catch {}
  applyTheme(saved);
}

async function init() {
  myIdentity = SecnetIdentity.loadOrCreateIdentity();
  myFingerprint = SecnetIdentity.fingerprint(myIdentity.publicKey);
  el('myFingerprint').textContent = myFingerprint;
  el('myPublicKey').textContent = SecnetIdentity.toB64(myIdentity.publicKey);

  if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
    Notification.requestPermission();
  }

  initTheme();
  renderContactList();
  renderUnknownSenders();
  setCallUIState('idle', '');
  setSignalState('searching', 'Searching for link\u2026');
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
        fromPublicKey: SecnetIdentity.toB64(myIdentity.publicKey),
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
    const mime = file.type || (mediaType === 'image' ? 'image/jpeg' : 'audio/webm');

    await enqueue(async () => {
      const ratchet = getRatchet(fingerprint);
      if (!ratchet) throw new Error('No secure session with this contact yet.');

      const CHUNK_SIZE = 8000;
      const mediaId = await sha256Hex(bytes);
      const totalChunks = Math.ceil(bytes.length / CHUNK_SIZE) || 1;

      // Each chunk is its OWN WebSocket message, not bundled — avoids
      // proxy message-size limits and connection instability on
      // larger files.
      //
      // Flow control: firing all chunks in a tight loop lets the
      // browser's outgoing WS buffer (bufferedAmount) pile up faster
      // than the network drains it. That's what causes the 30-60s
      // stalls on slow links, and on some hosts/proxies a backed-up
      // socket starts dropping frames — which shows up on the
      // receiving end as a SubtleCrypto decrypt error (the arriving
      // chunk is corrupt/incomplete, not actually a crypto bug).
      // Waiting for the buffer to drain before each send fixes both.
      const MAX_BUFFERED = 256 * 1024; // 256KB
      for (let i = 0; i < totalChunks; i++) {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
          throw new Error(`Connection dropped mid-transfer (chunk ${i + 1}/${totalChunks}) — try sending again.`);
        }

        while (ws.bufferedAmount > MAX_BUFFERED) {
          await new Promise((r) => setTimeout(r, 50));
          if (!ws || ws.readyState !== WebSocket.OPEN) {
            throw new Error(`Connection dropped mid-transfer (chunk ${i + 1}/${totalChunks}) — try sending again.`);
          }
        }

        const raw = bytes.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
        const aad = new TextEncoder().encode(`${mediaId}:${mediaType}`);
        let packet;
        try {
          packet = await ratchet.encrypt(raw, aad);
        } catch (cryptoErr) {
          throw new Error(`Encryption failed on chunk ${i + 1}/${totalChunks}: ${cryptoErr.message}`);
        }
        persistRatchet(fingerprint);

        ws.send(JSON.stringify({
          type: 'relay',
          to: fingerprint,
          fromPublicKey: SecnetIdentity.toB64(myIdentity.publicKey),
          packet: {
            kind: 'media_chunk',
            mediaId,
            mediaType,
            mime,
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

// ---- Voice calls (WebRTC, signaling relayed as encrypted packets) ----
//
// WebRTC media itself is always protected end-to-end by mandatory
// DTLS-SRTP, regardless of who relays the signaling. We additionally
// encrypt the SDP offers/answers/ICE candidates with the same ratchet
// used for messages, so the relay server — which already can't read
// chat content — also can't see call metadata (who's calling whom).
//
// LIMITATION: only a public STUN server is configured, no TURN. Calls
// between two people who are both behind strict/symmetric NATs may
// fail to connect — that needs a TURN relay, which isn't set up here.
// Works fine for most home wifi / mobile connections.
//
// LIMITATION: getUserMedia/RTCPeerConnection require a secure context
// (HTTPS, or localhost). If server.js fell back to plain HTTP because
// key.pem/cert.pem are missing, calls will fail to even request the
// microphone — that's a browser restriction, not a bug here.

const ICE_SERVERS = [{ urls: 'stun:stun.l.google.com:19302' }];

let currentCall = null; // { fingerprint, pc, localStream, role: 'caller'|'callee', pendingOffer? }

function callAad(subkind) {
  return new TextEncoder().encode(`call:${subkind}`);
}

async function sendCallSignal(fingerprint, subkind, data) {
  if (!ws || ws.readyState !== WebSocket.OPEN) throw new Error('Not connected to the server right now.');
  await enqueue(async () => {
    const ratchet = getRatchet(fingerprint);
    if (!ratchet) throw new Error('No secure session with this contact yet.');
    const bytes = new TextEncoder().encode(JSON.stringify(data));
    const packet = await ratchet.encrypt(bytes, callAad(subkind));
    persistRatchet(fingerprint);
    ws.send(JSON.stringify({
      type: 'relay',
      to: fingerprint,
      fromPublicKey: SecnetIdentity.toB64(myIdentity.publicKey),
      packet: { kind: `call_${subkind}`, packet: packetToJSON(packet) },
    }));
  });
}

function setCallUIState(state, label) {
  // state: 'idle' | 'calling' | 'active'
  const callBtn = el('callBtn');
  const endBtn = el('endCallBtn');
  const status = el('callStatus');
  if (!callBtn || !endBtn || !status) return;
  const busy = state !== 'idle';
  callBtn.style.display = busy ? 'none' : 'inline-block';
  endBtn.style.display = busy ? 'inline-block' : 'none';
  status.style.display = busy ? 'inline' : 'none';
  status.textContent = label || '';
}

function createPeerConnection(fingerprint) {
  const pc = new RTCPeerConnection({ iceServers: ICE_SERVERS });

  pc.onicecandidate = (e) => {
    if (e.candidate) {
      sendCallSignal(fingerprint, 'ice', { candidate: e.candidate }).catch((err) => {
        console.error('Could not send ICE candidate:', err);
      });
    }
  };

  pc.ontrack = (e) => {
    const audio = el('remoteAudio');
    if (audio) audio.srcObject = e.streams[0];
  };

  pc.onconnectionstatechange = () => {
    if (!currentCall || currentCall.pc !== pc) return;
    if (pc.connectionState === 'connected') {
      const contact = SecnetContacts.getContact(fingerprint);
      setCallUIState('active', 'On call \u2014 ' + (contact ? contact.name : fingerprint));
    } else if (pc.connectionState === 'failed' || pc.connectionState === 'disconnected' || pc.connectionState === 'closed') {
      endCall(fingerprint, false);
    }
  };

  return pc;
}

async function startCall(fingerprint) {
  if (!fingerprint) return;
  if (currentCall) {
    showError('Already in a call \u2014 end it before starting another.');
    return;
  }
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    showError('Not connected to the server right now \u2014 wait for reconnect and try again.');
    return;
  }
  const contact = SecnetContacts.getContact(fingerprint);
  if (!contact) return;

  try {
    const localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const pc = createPeerConnection(fingerprint);
    localStream.getTracks().forEach((t) => pc.addTrack(t, localStream));

    currentCall = { fingerprint, pc, localStream, role: 'caller' };
    setCallUIState('calling', 'Calling ' + contact.name + '\u2026');

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    await sendCallSignal(fingerprint, 'offer', { sdp: offer });
  } catch (err) {
    showError('Could not start call: ' + err.message);
    endCall(fingerprint, false);
  }
}

function showIncomingCallBanner(fingerprint) {
  const contact = SecnetContacts.getContact(fingerprint);
  el('incomingCallFrom').textContent = contact ? contact.name : fingerprint;
  el('incomingCallBanner').style.display = 'block';
  el('incomingCallBanner').dataset.fingerprint = fingerprint;
  flashTitle();
}
function hideIncomingCallBanner() {
  el('incomingCallBanner').style.display = 'none';
  delete el('incomingCallBanner').dataset.fingerprint;
}

function handleIncomingOffer(fromFingerprint, data) {
  if (currentCall) {
    // Busy with another call — decline quietly instead of leaving them hanging.
    sendCallSignal(fromFingerprint, 'end', { reason: 'busy' }).catch(() => {});
    return;
  }
  const contact = SecnetContacts.getContact(fromFingerprint);
  if (!contact) return; // same rule as messages: must be an added contact to interact

  currentCall = { fingerprint: fromFingerprint, pc: null, localStream: null, role: 'callee', pendingOffer: data.sdp };
  showIncomingCallBanner(fromFingerprint);
}

async function acceptCall() {
  const fingerprint = el('incomingCallBanner').dataset.fingerprint;
  if (!fingerprint || !currentCall || currentCall.fingerprint !== fingerprint) return;
  hideIncomingCallBanner();
  stopFlashingTitle();

  try {
    const localStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const pc = createPeerConnection(fingerprint);
    localStream.getTracks().forEach((t) => pc.addTrack(t, localStream));

    await pc.setRemoteDescription(new RTCSessionDescription(currentCall.pendingOffer));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    currentCall.pc = pc;
    currentCall.localStream = localStream;
    delete currentCall.pendingOffer;

    setCallUIState('active', 'Connecting\u2026');
    openContact(fingerprint);
    await sendCallSignal(fingerprint, 'answer', { sdp: answer });
  } catch (err) {
    showError('Could not accept call: ' + err.message);
    endCall(fingerprint, true);
  }
}

function declineCall() {
  const fingerprint = el('incomingCallBanner').dataset.fingerprint;
  hideIncomingCallBanner();
  if (fingerprint) sendCallSignal(fingerprint, 'end', { reason: 'declined' }).catch(() => {});
  currentCall = null;
}

async function handleIncomingAnswer(fromFingerprint, data) {
  if (!currentCall || currentCall.fingerprint !== fromFingerprint || !currentCall.pc) return;
  await currentCall.pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
}

async function handleIncomingIce(fromFingerprint, data) {
  if (!currentCall || currentCall.fingerprint !== fromFingerprint || !currentCall.pc) return;
  try {
    await currentCall.pc.addIceCandidate(new RTCIceCandidate(data.candidate));
  } catch (err) {
    console.error('Could not add ICE candidate:', err);
  }
}

function handleIncomingEnd(fromFingerprint) {
  if (!currentCall || currentCall.fingerprint !== fromFingerprint) return;
  if (el('incomingCallBanner').dataset.fingerprint === fromFingerprint) hideIncomingCallBanner();
  endCall(fromFingerprint, false);
}

function endCall(fingerprint, notifyPeer) {
  const target = fingerprint || (currentCall && currentCall.fingerprint);

  if (currentCall && currentCall.pc) {
    try { currentCall.pc.close(); } catch {}
  }
  if (currentCall && currentCall.localStream) {
    currentCall.localStream.getTracks().forEach((t) => t.stop());
  }
  const audio = el('remoteAudio');
  if (audio) audio.srcObject = null;

  currentCall = null;
  setCallUIState('idle', '');

  if (notifyPeer && target) {
    sendCallSignal(target, 'end', { reason: 'hangup' }).catch(() => {});
  }
}

window.addEventListener('beforeunload', () => {
  if (currentCall) endCall(currentCall.fingerprint, true);
});

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
  document.querySelectorAll('.theme-swatch').forEach((btn) => {
    btn.addEventListener('click', () => applyTheme(btn.dataset.themeOption));
  });
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

  el('callBtn').addEventListener('click', () => startCall(activeFingerprint));
  el('endCallBtn').addEventListener('click', () => {
    if (currentCall) endCall(currentCall.fingerprint, true);
  });
  el('acceptCallBtn').addEventListener('click', acceptCall);
  el('declineCallBtn').addEventListener('click', declineCall);
});
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
  document.querySelectorAll('.theme-swatch').forEach((btn) => {
    btn.addEventListener('click', () => applyTheme(btn.dataset.themeOption));
  });
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
