/* ═══════════════════════════════════════════════════════════════════
   Vault – Main App Controller
   Manages UI, Socket.io events, encryption orchestration.
   ═══════════════════════════════════════════════════════════════════ */

(async function () {
  'use strict';

  // ── State ──────────────────────────────────────────────────────
  let socket        = null;
  let myUsername     = null;
  let myKeyPair     = null;          // { publicKey, privateKey } CryptoKey
  let myPublicJwk   = null;
  let activeChat     = null;          // username of current chat partner
  let sharedKeys     = {};            // username → AES CryptoKey (cache)
  let contacts       = [];            // [{ username, publicKey (JWK), online }]
  let chatMessages   = {};            // username → [{ from, text, timestamp }]
  let unreadCounts   = {};            // username → number
  let typingTimers   = {};            // incoming typing timeout ids
  let myTypingTimer  = null;          // outgoing typing debounce
  let isSendingTyping = false;

  // ── DOM refs ───────────────────────────────────────────────────
  const $ = (sel) => document.querySelector(sel);
  const loginView     = $('#login-view');
  const chatView      = $('#chat-view');
  const usernameInput = $('#username-input');
  const loginBtn      = $('#login-btn');
  const loginError    = $('#login-error');
  const myBadge       = $('#my-badge');
  const userSearch    = $('#user-search');
  const userList      = $('#user-list');
  const noUsers       = $('#no-users');
  const emptyState    = $('#empty-state');
  const activeEl      = $('#active-chat');
  const chatAvatar    = $('#chat-avatar');
  const chatName      = $('#chat-name');
  const chatStatus    = $('#chat-status');
  const encBadge      = $('#enc-badge');
  const messagesEl    = $('#messages');
  const typingInd     = $('#typing-indicator');
  const typingLabel   = $('#typing-label');
  const msgInput      = $('#message-input');
  const sendBtn       = $('#send-btn');

  // ═══ INIT ══════════════════════════════════════════════════════
  usernameInput.addEventListener('input', () => {
    loginBtn.disabled = !usernameInput.value.trim();
  });
  usernameInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !loginBtn.disabled) doLogin();
  });
  loginBtn.addEventListener('click', doLogin);
  msgInput.addEventListener('input', onMessageInput);
  msgInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !sendBtn.disabled) doSend();
  });
  sendBtn.addEventListener('click', doSend);
  userSearch.addEventListener('input', renderContacts);

  // ═══ LOGIN ═════════════════════════════════════════════════════
  async function doLogin() {
    const username = usernameInput.value.trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (!username) return;

    loginBtn.disabled = true;
    loginBtn.querySelector('.btn-text').textContent = 'Connecting…';
    hideError();

    try {
      // 1. Load or generate ECDH key pair
      const stored = VaultCrypto.loadKeyPair(username);
      if (stored) {
        myKeyPair = {
          publicKey: await VaultCrypto.importPublicKey(stored.publicJwk),
          privateKey: await VaultCrypto.importPrivateKey(stored.privateJwk),
        };
        myPublicJwk = stored.publicJwk;
      } else {
        myKeyPair = await VaultCrypto.generateKeyPair();
        myPublicJwk = await VaultCrypto.exportPublicKey(myKeyPair.publicKey);
        const privJwk = await VaultCrypto.exportPrivateKey(myKeyPair.privateKey);
        VaultCrypto.storeKeyPair(username, myPublicJwk, privJwk);
      }

      // 2. Connect socket
      socket = io({ transports: ['websocket', 'polling'] });

      await new Promise((resolve, reject) => {
        socket.on('connect', resolve);
        socket.on('connect_error', (err) => reject(new Error('Connection failed')));
        setTimeout(() => reject(new Error('Connection timeout')), 8000);
      });

      // 3. Register with server
      const res = await emitAsync('register', {
        username,
        publicKey: myPublicJwk,
      });

      if (res.error) throw new Error(res.error);

      myUsername = username;
      contacts = res.contacts || [];

      // 4. Bind socket events
      bindSocketEvents();

      // 5. Switch to chat view
      loginView.classList.remove('active');
      chatView.classList.add('active');
      myBadge.textContent = `@${myUsername}`;
      renderContacts();

    } catch (err) {
      showError(err.message);
      loginBtn.querySelector('.btn-text').textContent = 'Connect Securely';
      loginBtn.disabled = false;
      if (socket) { socket.disconnect(); socket = null; }
    }
  }

  // ═══ SOCKET EVENTS ═════════════════════════════════════════════
  function bindSocketEvents() {
    socket.on('user-status', ({ username, online }) => {
      const c = contacts.find(u => u.username === username);
      if (c) {
        c.online = online;
      } else if (username !== myUsername) {
        // New user registered — fetch their public key
        socket.emit('get-public-key', { username }, (res) => {
          if (res.publicKey) {
            contacts.push({ username, publicKey: res.publicKey, online });
          }
          renderContacts();
        });
        return;
      }
      renderContacts();
      if (activeChat === username) updateChatHeader();
    });

    socket.on('online-users', (list) => {
      contacts.forEach(c => c.online = list.includes(c.username));
      renderContacts();
      if (activeChat) updateChatHeader();
    });

    socket.on('encrypted-message', async (msg) => {
      try {
        const key = await getSharedKey(msg.from);
        const text = await VaultCrypto.decrypt(key, msg.ciphertext, msg.iv);

        if (!chatMessages[msg.from]) chatMessages[msg.from] = [];
        chatMessages[msg.from].push({
          from: msg.from,
          text,
          timestamp: msg.timestamp,
        });

        if (activeChat === msg.from) {
          appendMessage(msg.from, text, msg.timestamp, false);
          scrollToBottom();
        } else {
          unreadCounts[msg.from] = (unreadCounts[msg.from] || 0) + 1;
          renderContacts();
        }
      } catch (err) {
        console.error('Decryption failed:', err);
      }
    });

    socket.on('user-typing', ({ from }) => {
      if (from === activeChat) showTyping(from);
    });

    socket.on('user-stop-typing', ({ from }) => {
      if (from === activeChat) hideTyping();
    });
  }

  // ═══ CONTACTS LIST ═════════════════════════════════════════════
  function renderContacts() {
    const query = userSearch.value.toLowerCase();
    const filtered = contacts
      .filter(c => c.username.includes(query))
      .sort((a, b) => {
        // Online first, then alphabetical
        if (a.online !== b.online) return a.online ? -1 : 1;
        return a.username.localeCompare(b.username);
      });

    userList.innerHTML = '';
    noUsers.hidden = filtered.length > 0;

    filtered.forEach(c => {
      const li = document.createElement('li');
      li.id = `contact-${c.username}`;
      if (c.username === activeChat) li.classList.add('active');

      const lastMsg = chatMessages[c.username]?.slice(-1)[0];
      const preview = lastMsg
        ? (lastMsg.from === myUsername ? 'You: ' : '') + truncate(lastMsg.text, 28)
        : 'No messages yet';
      const unread = unreadCounts[c.username] || 0;

      li.innerHTML = `
        <div class="avatar">${c.username[0]}</div>
        <div class="user-info">
          <span class="user-name">${esc(c.username)}</span>
          <span class="user-preview">${esc(preview)}</span>
        </div>
        <div class="status-dot ${c.online ? 'online' : 'offline'}"></div>
        ${unread ? `<span class="unread-badge">${unread}</span>` : ''}
      `;

      li.addEventListener('click', () => openChat(c.username));
      userList.appendChild(li);
    });
  }

  // ═══ OPEN CHAT ═════════════════════════════════════════════════
  async function openChat(username) {
    if (activeChat === username) return;
    activeChat = username;
    unreadCounts[username] = 0;

    // UI
    emptyState.style.display = 'none';
    activeEl.hidden = false;
    messagesEl.innerHTML = '';
    hideTyping();
    updateChatHeader();
    renderContacts();
    msgInput.focus();

    // Derive shared key (cached)
    try {
      await getSharedKey(username);
    } catch (err) {
      console.error('Key derivation failed:', err);
      return;
    }

    // Load encrypted history from server
    const res = await emitAsync('load-history', { withUser: username });
    const history = res.messages || [];

    // Decrypt and display
    chatMessages[username] = [];
    const key = sharedKeys[username];

    for (const msg of history) {
      try {
        const text = await VaultCrypto.decrypt(key, msg.ciphertext, msg.iv);
        chatMessages[username].push({
          from: msg.from,
          text,
          timestamp: msg.timestamp,
        });
      } catch {
        chatMessages[username].push({
          from: msg.from,
          text: '⚠️ Unable to decrypt (key mismatch)',
          timestamp: msg.timestamp,
        });
      }
    }

    renderAllMessages(username);
    scrollToBottom();
    sendBtn.disabled = false;
  }

  function updateChatHeader() {
    if (!activeChat) return;
    const c = contacts.find(u => u.username === activeChat);
    chatAvatar.textContent = activeChat[0].toUpperCase();
    chatName.textContent = activeChat;
    chatStatus.textContent = c?.online ? 'online' : 'offline';
    chatStatus.className = 'chat-status' + (c?.online ? ' online' : '');
  }

  // ═══ MESSAGES ══════════════════════════════════════════════════
  function renderAllMessages(username) {
    messagesEl.innerHTML = '';
    const msgs = chatMessages[username] || [];
    let lastDate = '';
    msgs.forEach(m => {
      const d = new Date(m.timestamp).toLocaleDateString();
      if (d !== lastDate) {
        lastDate = d;
        const sep = document.createElement('div');
        sep.className = 'date-sep';
        sep.textContent = formatDate(m.timestamp);
        messagesEl.appendChild(sep);
      }
      appendMessage(m.from, m.text, m.timestamp, m.from === myUsername);
    });
  }

  function appendMessage(from, text, timestamp, sent) {
    const isMine = from === myUsername;
    const div = document.createElement('div');
    div.className = `msg ${isMine ? 'sent' : 'received'}`;
    div.innerHTML = `
      <span class="msg-text">${esc(text)}</span>
      <span class="msg-time">${formatTime(timestamp)}</span>
    `;
    messagesEl.appendChild(div);
  }

  function scrollToBottom() {
    requestAnimationFrame(() => {
      messagesEl.scrollTop = messagesEl.scrollHeight;
    });
  }

  // ═══ SEND MESSAGE ══════════════════════════════════════════════
  async function doSend() {
    const text = msgInput.value.trim();
    if (!text || !activeChat) return;

    msgInput.value = '';
    sendBtn.disabled = true;
    emitStopTyping();

    try {
      const key = await getSharedKey(activeChat);
      const { ciphertext, iv } = await VaultCrypto.encrypt(key, text);

      socket.emit('encrypted-message', {
        to: activeChat,
        ciphertext,
        iv,
      });

      // Store locally
      const ts = Date.now();
      if (!chatMessages[activeChat]) chatMessages[activeChat] = [];
      chatMessages[activeChat].push({ from: myUsername, text, timestamp: ts });

      appendMessage(myUsername, text, ts, true);
      scrollToBottom();
      renderContacts();
    } catch (err) {
      console.error('Send failed:', err);
    }

    sendBtn.disabled = false;
    msgInput.focus();
  }

  // ═══ TYPING INDICATORS ════════════════════════════════════════
  function onMessageInput() {
    sendBtn.disabled = !msgInput.value.trim();
    if (!activeChat) return;

    if (!isSendingTyping) {
      isSendingTyping = true;
      socket.emit('typing', { to: activeChat });
    }

    clearTimeout(myTypingTimer);
    myTypingTimer = setTimeout(() => {
      emitStopTyping();
    }, 2000);
  }

  function emitStopTyping() {
    if (isSendingTyping && activeChat) {
      socket.emit('stop-typing', { to: activeChat });
      isSendingTyping = false;
    }
    clearTimeout(myTypingTimer);
  }

  function showTyping(from) {
    typingLabel.textContent = `${from} is typing…`;
    typingInd.hidden = false;
    scrollToBottom();

    clearTimeout(typingTimers[from]);
    typingTimers[from] = setTimeout(() => hideTyping(), 3000);
  }

  function hideTyping() {
    typingInd.hidden = true;
  }

  // ═══ KEY MANAGEMENT ════════════════════════════════════════════
  async function getSharedKey(username) {
    if (sharedKeys[username]) return sharedKeys[username];

    // Get peer's public key
    const contact = contacts.find(c => c.username === username);
    let peerPubJwk = contact?.publicKey;

    if (!peerPubJwk) {
      const res = await emitAsync('get-public-key', { username });
      if (res.error) throw new Error(res.error);
      peerPubJwk = res.publicKey;
    }

    const peerPubKey = await VaultCrypto.importPublicKey(peerPubJwk);
    const shared = await VaultCrypto.deriveSharedKey(myKeyPair.privateKey, peerPubKey);
    sharedKeys[username] = shared;
    return shared;
  }

  // ═══ HELPERS ═══════════════════════════════════════════════════
  function emitAsync(event, data) {
    return new Promise((resolve) => {
      socket.emit(event, data, (res) => resolve(res));
    });
  }

  function esc(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function truncate(str, max) {
    return str.length > max ? str.slice(0, max) + '…' : str;
  }

  function formatTime(ts) {
    return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function formatDate(ts) {
    const d = new Date(ts);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(today.getDate() - 1);

    if (d.toDateString() === today.toDateString()) return 'Today';
    if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
    return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
  }

  function showError(msg) {
    loginError.textContent = msg;
    loginError.hidden = false;
  }
  function hideError() {
    loginError.hidden = true;
  }
})();
