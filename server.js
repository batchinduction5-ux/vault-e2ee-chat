const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const fs = require('fs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { maxHttpBufferSize: 10 * 1024 * 1024 });

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ─── Persistent Storage ───────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadJSON(file, fallback) {
  try {
    if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) { console.error(`Error loading ${file}:`, e.message); }
  return fallback;
}

function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// { username: { publicKey: JWK } }
let users = loadJSON(USERS_FILE, {});
// [{ id, from, to, ciphertext, iv, timestamp }]
let messages = loadJSON(MESSAGES_FILE, []);

function saveUsers() { saveJSON(USERS_FILE, users); }
function saveMessages() { saveJSON(MESSAGES_FILE, messages); }

// ─── Presence Tracking ───────────────────────────────────────────────
const onlineUsers = new Map();   // socketId → username
const userSockets = new Map();   // username → socketId

function broadcastPresence() {
  const list = Array.from(userSockets.keys());
  io.emit('online-users', list);
}

// ─── Socket.io Events ───────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log(`⚡ Connected: ${socket.id}`);

  // ── Register / Login ──────────────────────────────────────────────
  socket.on('register', ({ username, publicKey }, cb) => {
    if (!username || !publicKey) return cb({ error: 'Missing fields' });

    // If someone else is actively using this name, reject
    if (userSockets.has(username) && userSockets.get(username) !== socket.id) {
      return cb({ error: 'Username is currently in use' });
    }

    users[username] = { publicKey };
    saveUsers();

    onlineUsers.set(socket.id, username);
    userSockets.set(username, socket.id);

    // Build contact list (all other registered users)
    const contacts = Object.keys(users)
      .filter(u => u !== username)
      .map(u => ({
        username: u,
        publicKey: users[u].publicKey,
        online: userSockets.has(u),
      }));

    cb({ success: true, contacts });

    // Notify everyone
    io.emit('user-status', { username, online: true });
    broadcastPresence();
    console.log(`🟢 Registered: ${username}`);
  });

  // ── Fetch a user's public key ─────────────────────────────────────
  socket.on('get-public-key', ({ username }, cb) => {
    if (users[username]) cb({ publicKey: users[username].publicKey });
    else cb({ error: 'User not found' });
  });

  // ── Encrypted message relay + storage ─────────────────────────────
  socket.on('encrypted-message', (data) => {
    const from = onlineUsers.get(socket.id);
    if (!from) return;

    const msg = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 9),
      from,
      to: data.to,
      ciphertext: data.ciphertext,
      iv: data.iv,
      timestamp: Date.now(),
    };

    messages.push(msg);
    saveMessages();

    // Relay to recipient if online
    const dest = userSockets.get(data.to);
    if (dest) io.to(dest).emit('encrypted-message', msg);

    // Acknowledge to sender
    socket.emit('message-sent', { id: msg.id, timestamp: msg.timestamp });
  });

  // ── Load encrypted history ────────────────────────────────────────
  socket.on('load-history', ({ withUser }, cb) => {
    const me = onlineUsers.get(socket.id);
    if (!me) return cb({ messages: [] });

    const history = messages
      .filter(m =>
        (m.from === me && m.to === withUser) ||
        (m.from === withUser && m.to === me)
      )
      .sort((a, b) => a.timestamp - b.timestamp);

    cb({ messages: history });
  });

  // ── Typing indicators ────────────────────────────────────────────
  socket.on('typing', ({ to }) => {
    const from = onlineUsers.get(socket.id);
    if (!from) return;
    const dest = userSockets.get(to);
    if (dest) io.to(dest).emit('user-typing', { from });
  });

  socket.on('stop-typing', ({ to }) => {
    const from = onlineUsers.get(socket.id);
    if (!from) return;
    const dest = userSockets.get(to);
    if (dest) io.to(dest).emit('user-stop-typing', { from });
  });
  // ── WebRTC Call Signaling ──────────────────────────────────────────
  socket.on('call-offer', ({ to, offer, callType }) => {
    const from = onlineUsers.get(socket.id);
    if (!from) return;
    const dest = userSockets.get(to);
    if (dest) io.to(dest).emit('call-offer', { from, offer, callType });
    else socket.emit('call-rejected', { from: to, reason: 'User is offline' });
  });

  socket.on('call-answer', ({ to, answer }) => {
    const from = onlineUsers.get(socket.id);
    if (!from) return;
    const dest = userSockets.get(to);
    if (dest) io.to(dest).emit('call-answer', { from, answer });
  });

  socket.on('ice-candidate', ({ to, candidate }) => {
    const from = onlineUsers.get(socket.id);
    if (!from) return;
    const dest = userSockets.get(to);
    if (dest) io.to(dest).emit('ice-candidate', { from, candidate });
  });

  socket.on('call-reject', ({ to }) => {
    const from = onlineUsers.get(socket.id);
    if (!from) return;
    const dest = userSockets.get(to);
    if (dest) io.to(dest).emit('call-rejected', { from });
  });

  socket.on('call-end', ({ to }) => {
    const from = onlineUsers.get(socket.id);
    if (!from) return;
    const dest = userSockets.get(to);
    if (dest) io.to(dest).emit('call-ended', { from });
  });

  // ── Disconnect ────────────────────────────────────────────────────
  socket.on('disconnect', () => {
    const username = onlineUsers.get(socket.id);
    if (username) {
      onlineUsers.delete(socket.id);
      userSockets.delete(username);
      io.emit('user-status', { username, online: false });
      broadcastPresence();
      console.log(`🔴 Disconnected: ${username}`);
    }
  });
});

// ─── Start ───────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`\n🔒 Vault E2EE Chat Server`);
  console.log(`   http://localhost:${PORT}\n`);
});
