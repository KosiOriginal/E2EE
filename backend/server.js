'use strict';
/**
 * server.js — Relay server for the private chat network.
 *
 * IMPORTANT SECURITY PROPERTY: this server NEVER decrypts anything.
 * It only does:
 *   1. Bulletin board — stores public keys/prekey bundles so people
 *      can start a conversation with someone currently offline.
 *   2. Mailbox / relay — forwards encrypted packets between clients,
 *      and PERSISTS them to disk if the recipient isn't connected
 *      right now, so a server restart doesn't lose queued messages.
 *
 * Everything here is stored in SQLite (data.db, created automatically
 * next to this file). Only ciphertext ever touches this database —
 * the server has no way to read message content.
 */

const express = require('express');
const path = require('path');
const https = require('https');
const http = require('http');
const fs = require('fs');
const WebSocket = require('ws'); // npm install ws
const { DatabaseSync } = require('node:sqlite');

const app = express();
const PORT = process.env.PORT || 9000;

app.use(express.json({ limit: '10mb' })); // media chunks can be sizeable
app.use(express.static(path.join(__dirname, '..', 'frontend')));

// ---- Persistent storage ----

const db = new DatabaseSync(path.join(__dirname, 'data.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS bundles (
    fingerprint TEXT PRIMARY KEY,
    bundle_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS mailbox (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_fingerprint TEXT NOT NULL,
    from_fingerprint TEXT NOT NULL,
    packet_json TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox (recipient_fingerprint);
`);

const stmts = {
  upsertBundle: db.prepare(
    'INSERT INTO bundles (fingerprint, bundle_json, updated_at) VALUES (?, ?, ?) ' +
    'ON CONFLICT(fingerprint) DO UPDATE SET bundle_json = excluded.bundle_json, updated_at = excluded.updated_at'
  ),
  getBundle: db.prepare('SELECT bundle_json FROM bundles WHERE fingerprint = ?'),
  queueMessage: db.prepare(
    'INSERT INTO mailbox (recipient_fingerprint, from_fingerprint, packet_json, created_at) VALUES (?, ?, ?, ?)'
  ),
  getMailbox: db.prepare(
    'SELECT id, from_fingerprint, packet_json FROM mailbox WHERE recipient_fingerprint = ? ORDER BY id ASC'
  ),
  deleteMailboxEntry: db.prepare('DELETE FROM mailbox WHERE id = ?'),
};

function queueMessage(recipientFingerprint, fromFingerprint, packet) {
  stmts.queueMessage.run(recipientFingerprint, fromFingerprint, JSON.stringify(packet), Date.now());
}

function flushMailbox(fingerprint, ws) {
  const rows = stmts.getMailbox.all(fingerprint);
  for (const row of rows) {
    // Same flat shape as live delivery below — from, packet, both present.
    ws.send(JSON.stringify({
      type: 'relay',
      from: row.from_fingerprint,
      packet: JSON.parse(row.packet_json),
    }));
    stmts.deleteMailboxEntry.run(row.id);
  }
}

// ---- REST: publishing / fetching prekey bundles (for the X3DH handshake) ----

app.post('/api/publish-bundle', (req, res) => {
  const { fingerprint, bundle } = req.body;
  if (!fingerprint || !bundle) {
    return res.status(400).json({ error: 'fingerprint and bundle required' });
  }
  stmts.upsertBundle.run(fingerprint, JSON.stringify(bundle), Date.now());
  res.json({ ok: true });
});

app.get('/api/bundle/:fingerprint', (req, res) => {
  const row = stmts.getBundle.get(req.params.fingerprint);
  if (!row) return res.status(404).json({ error: 'no bundle published for this fingerprint' });
  res.json({ bundle: JSON.parse(row.bundle_json) });
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
const connectedClients = new Map(); // fingerprint -> ws (only live, in-memory — fine to lose on restart)

wss.on('connection', (ws) => {
  let myFingerprint = null;

  ws.on('message', (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw);
    } catch {
      return;
    }

    if (msg.type === 'register') {
      myFingerprint = msg.fingerprint;
      console.log(`[register] ${myFingerprint}`);
      connectedClients.set(myFingerprint, ws);
      console.log(`[connected clients]`, [...connectedClients.keys()]);
      flushMailbox(myFingerprint, ws);
      return;
    }

    if (msg.type === 'relay') {
      console.log(`[relay attempt] from=${myFingerprint} to=${msg.to}`);
      const recipientWs = connectedClients.get(msg.to);
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        console.log(`[relay] recipient online, delivering directly`);
        recipientWs.send(JSON.stringify({ type: 'relay', from: myFingerprint, packet: msg.packet }));
      } else {
        console.log(`[relay] recipient NOT connected, queuing. Known clients:`, [...connectedClients.keys()]);
        queueMessage(msg.to, myFingerprint, msg.packet);
      }
      return;
    }
  });

  ws.on('close', () => {
    if (myFingerprint) {
      console.log(`[disconnect] ${myFingerprint}`);
      connectedClients.delete(myFingerprint);
    }
  });
});
