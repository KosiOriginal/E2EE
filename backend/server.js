'use strict';
/**
 * server.js — Relay server for the private chat network.
 *
 * IMPORTANT SECURITY PROPERTY: this server NEVER decrypts anything.
 * It only does two jobs:
 *   1. Bulletin board — stores public prekey bundles so people can
 *      start a conversation with someone who's currently offline.
 *   2. Mailbox / relay — forwards encrypted packets between clients,
 *      and queues them in memory if the recipient isn't connected
 *      right now (this is "store-and-forward").
 *
 * The server operator (you, or whoever hosts this) can NEVER read
 * message content — only ciphertext passes through here. All the
 * actual encryption/decryption happens on each user's device
 * (in the frontend, using crypto_core logic).
 */

const express = require('express');
const path = require('path');
const https = require('https');
const http = require('http');
const fs = require('fs');
const WebSocket = require('ws'); // npm install ws

const app = express();
const PORT = process.env.PORT || 9000;

app.use(express.json({ limit: '10mb' })); // media chunks can be sizeable
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ---- In-memory state (swap for a real DB later if you want persistence) ----

// fingerprint -> { ws, lastSeen }
const connectedClients = new Map();

// fingerprint -> published prekey bundle (public parts only!)
const publishedBundles = new Map();

// fingerprint -> array of queued encrypted packets waiting for them to connect
const mailboxes = new Map();

function queueMessage(recipientFingerprint, packet) {
  if (!mailboxes.has(recipientFingerprint)) {
    mailboxes.set(recipientFingerprint, []);
  }
  mailboxes.get(recipientFingerprint).push(packet);
}

function flushMailbox(fingerprint, ws) {
  const queued = mailboxes.get(fingerprint) || [];
  for (const qMsg of queued) {
    // Разопаковаме qMsg правилно
    ws.send(JSON.stringify({ type: 'relay', from: qMsg.from, packet: qMsg.packet }));
  }
  mailboxes.set(fingerprint, []);
}

// ---- REST: publishing / fetching prekey bundles (for the X3DH handshake) ----

// A device publishes its bundle once (public keys only) so others
// can start a session with it even while it's offline.
app.post('/api/publish-bundle', (req, res) => {
  const { fingerprint, bundle } = req.body;
  if (!fingerprint || !bundle) {
    return res.status(400).json({ error: 'fingerprint and bundle required' });
  }
  publishedBundles.set(fingerprint, bundle);
  res.json({ ok: true });
});

// Fetch someone's published bundle to start a session with them
app.get('/api/bundle/:fingerprint', (req, res) => {
  const bundle = publishedBundles.get(req.params.fingerprint);
  if (!bundle) return res.status(404).json({ error: 'no bundle published for this fingerprint' });
  res.json({ bundle });
});

// Serve the frontend for any other route
app.get(/.*/, (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'frontend', 'index.html'));
});

// ---- Start HTTPS (or fall back to HTTP) ----

let server;
try {
  const options = {
    key: fs.readFileSync(path.join(__dirname, 'key.pem')),
    cert: fs.readFileSync(path.join(__dirname, 'cert.pem')),
  };
  server = https.createServer(options, app);
  server.listen(PORT, () => console.log(`Secure server running on https://localhost:${PORT}`));
} catch (err) {
  console.error('Could not read key.pem/cert.pem — falling back to plain HTTP (NOT recommended).');
  server = http.createServer(app);
  server.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}

// ---- WebSocket layer: real-time relay of encrypted packets ----

const wss = new WebSocket.Server({ server });

wss.on('connection', (ws) => {
  let myFingerprint = null;

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return; // ignore malformed input
    }

    if (msg.type === 'register') {
      // Client announces "I am this fingerprint" after connecting.
      // (In a hardened version, add a signed challenge here so nobody
      // can falsely claim someone else's fingerprint.)
      myFingerprint = msg.fingerprint;
      connectedClients.set(myFingerprint, { ws, lastSeen: Date.now() });
      flushMailbox(myFingerprint, ws); // deliver anything queued while they were away
      return;
    }

    if (msg.type === 'relay') {
      // msg.to = recipient fingerprint, msg.packet = opaque encrypted blob
      // Server never inspects msg.packet's contents beyond routing it.
      const recipient = connectedClients.get(msg.to);
      if (recipient) {
        recipient.ws.send(JSON.stringify({ type: 'relay', from: myFingerprint, packet: msg.packet }));
      } else {
        queueMessage(msg.to, { from: myFingerprint, packet: msg.packet });
      }
      return;
    }
  });

  ws.on('close', () => {
    if (myFingerprint) connectedClients.delete(myFingerprint);
  });
});
