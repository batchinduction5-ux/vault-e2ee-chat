/* ═══════════════════════════════════════════════════════════════════
   Vault – Main App Controller
   Manages UI, Socket.io events, encryption orchestration.
   ═══════════════════════════════════════════════════════════════════ */

(async function () {
  'use strict';

  const MEDIA_PREFIX = '__VAULT_MEDIA__';
  const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5 MB

  // ── State ──────────────────────────────────────────────────────
  let socket         = null;
  let myUsername      = null;
  let myKeyPair      = null;
  let myPublicJwk    = null;
  let activeChat     = null;
  let sharedKeys     = {};
  let contacts       = [];
  let chatMessages   = {};
  let unreadCounts   = {};
  let typingTimers   = {};
  let myTypingTimer  = null;
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
  const messagesEl    = $('#messages');
  const typingInd     = $('#typing-indicator');
  const typingLabel   = $('#typing-label');
  const msgInput      = $('#message-input');
  const sendBtn       = $('#send-btn');
  const attachBtn     = $('#attach-btn');
  const fileInput     = $('#file-input');

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
  attachBtn.addEventListener('click', () => { if (activeChat) fileInput.click(); });
  fileInput.addEventListener('change', onFileSelected);

  // ═══ AUTO-LOGIN ════════════════════════════════════════════════
  const savedUser = localStorage.getItem('vault_username');
  if (savedUser && VaultCrypto.loadKeyPair(savedUser)) {
    usernameInput.value = savedUser;
    loginBtn.disabled = false;
    doLogin();
  }

  // ═══ LOGIN ═════════════════════════════════════════════════════
  async function doLogin() {
    const username = (usernameInput.value || '').trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    if (!username) return;

    loginBtn.disabled = true;
    loginBtn.querySelector('.btn-text').textContent = 'Connecting…';
    hideError();

    try {
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

      socket = io({ transports: ['websocket', 'polling'] });

      await new Promise((resolve, reject) => {
        socket.on('connect', resolve);
        socket.on('connect_error', () => reject(new Error('Connection failed')));
        setTimeout(() => reject(new Error('Connection timeout')), 8000);
      });

      const res = await emitAsync('register', { username, publicKey: myPublicJwk });
      if (res.error) throw new Error(res.error);

      myUsername = username;
      contacts = res.contacts || [];
      localStorage.setItem('vault_username', username);
      bindSocketEvents();

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
        socket.emit('get-public-key', { username }, (res) => {
          if (res.publicKey) contacts.push({ username, publicKey: res.publicKey, online });
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
        const raw = await VaultCrypto.decrypt(key, msg.ciphertext, msg.iv);
        const parsed = parseMessage(raw);

        if (!chatMessages[msg.from]) chatMessages[msg.from] = [];
        chatMessages[msg.from].push({ from: msg.from, ...parsed, timestamp: msg.timestamp });

        if (activeChat === msg.from) {
          appendMessageEl({ from: msg.from, ...parsed, timestamp: msg.timestamp });
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

  // ═══ MESSAGE PARSING ═══════════════════════════════════════════
  function parseMessage(raw) {
    if (raw.startsWith(MEDIA_PREFIX)) {
      try {
        const json = JSON.parse(raw.slice(MEDIA_PREFIX.length));
        return { type: 'media', name: json.name, mime: json.mime, data: json.data, size: json.size };
      } catch { return { type: 'text', text: '[corrupt media]' }; }
    }
    return { type: 'text', text: raw };
  }

  function buildPayload(msgObj) {
    if (msgObj.type === 'media') {
      return MEDIA_PREFIX + JSON.stringify({ name: msgObj.name, mime: msgObj.mime, data: msgObj.data, size: msgObj.size });
    }
    return msgObj.text;
  }

  // ═══ CONTACTS LIST ═════════════════════════════════════════════
  function renderContacts() {
    const query = userSearch.value.toLowerCase();
    const filtered = contacts
      .filter(c => c.username.includes(query))
      .sort((a, b) => {
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
      let preview = 'No messages yet';
      if (lastMsg) {
        const prefix = lastMsg.from === myUsername ? 'You: ' : '';
        preview = lastMsg.type === 'media' ? prefix + '📎 ' + lastMsg.name : prefix + truncate(lastMsg.text, 28);
      }
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

    emptyState.style.display = 'none';
    activeEl.hidden = false;
    messagesEl.innerHTML = '';
    hideTyping();
    updateChatHeader();
    renderContacts();
    msgInput.focus();

    try { await getSharedKey(username); }
    catch (err) { console.error('Key derivation failed:', err); return; }

    const res = await emitAsync('load-history', { withUser: username });
    chatMessages[username] = [];
    const key = sharedKeys[username];

    for (const msg of (res.messages || [])) {
      try {
        const raw = await VaultCrypto.decrypt(key, msg.ciphertext, msg.iv);
        const parsed = parseMessage(raw);
        chatMessages[username].push({ from: msg.from, ...parsed, timestamp: msg.timestamp });
      } catch {
        chatMessages[username].push({ from: msg.from, type: 'text', text: '⚠️ Unable to decrypt', timestamp: msg.timestamp });
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
      appendMessageEl(m);
    });
  }

  function appendMessageEl(m) {
    const isMine = m.from === myUsername;
    const div = document.createElement('div');
    div.className = `msg ${isMine ? 'sent' : 'received'}`;

    if (m.type === 'media') {
      div.innerHTML = renderMediaContent(m) +
        `<span class="msg-time">${formatTime(m.timestamp)}</span>`;
    } else {
      div.innerHTML = `<span class="msg-text">${esc(m.text)}</span>
        <span class="msg-time">${formatTime(m.timestamp)}</span>`;
    }

    messagesEl.appendChild(div);
  }

  function renderMediaContent(m) {
    const sizeStr = formatFileSize(m.size || 0);
    if (m.mime && m.mime.startsWith('image/')) {
      return `<div class="msg-media"><img src="data:${m.mime};base64,${m.data}" alt="${esc(m.name)}" onclick="window._vaultPreview(this.src,'img')"></div>
        <span class="msg-text" style="font-size:12px;opacity:.7">📷 ${esc(m.name)} (${sizeStr})</span>`;
    }
    if (m.mime && m.mime.startsWith('video/')) {
      return `<div class="msg-media"><video src="data:${m.mime};base64,${m.data}" controls></video></div>
        <span class="msg-text" style="font-size:12px;opacity:.7">🎬 ${esc(m.name)} (${sizeStr})</span>`;
    }
    if (m.mime && m.mime.startsWith('audio/')) {
      return `<div class="msg-media"><audio src="data:${m.mime};base64,${m.data}" controls style="width:100%"></audio></div>
        <span class="msg-text" style="font-size:12px;opacity:.7">🎵 ${esc(m.name)} (${sizeStr})</span>`;
    }
    // Generic file
    return `<div class="msg-file" onclick="window._vaultDownload('${btoa(m.name)}','${m.mime}','${m.data.slice(0, 50)}')">
      <span class="msg-file-icon">📄</span>
      <div class="msg-file-info">
        <span class="msg-file-name">${esc(m.name)}</span>
        <span class="msg-file-size">${sizeStr}</span>
      </div></div>`;
  }

  // Global helpers for inline event handlers
  window._vaultPreview = function (src, type) {
    const overlay = document.createElement('div');
    overlay.className = 'file-preview-overlay';
    overlay.innerHTML = type === 'img' ? `<img src="${src}">` : `<video src="${src}" controls autoplay>`;
    overlay.addEventListener('click', () => overlay.remove());
    document.body.appendChild(overlay);
  };

  window._vaultDownload = function (nameB64) {
    // Find the message data and trigger download
    const name = atob(nameB64);
    const msgs = chatMessages[activeChat] || [];
    const m = msgs.find(x => x.type === 'media' && x.name === name);
    if (!m) return;
    const blob = base64ToBlob(m.data, m.mime);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = m.name; a.click();
    URL.revokeObjectURL(url);
  };

  function base64ToBlob(b64, mime) {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new Blob([bytes], { type: mime });
  }

  function scrollToBottom() {
    requestAnimationFrame(() => { messagesEl.scrollTop = messagesEl.scrollHeight; });
  }

  // ═══ SEND TEXT MESSAGE ═════════════════════════════════════════
  async function doSend() {
    const text = msgInput.value.trim();
    if (!text || !activeChat) return;

    msgInput.value = '';
    sendBtn.disabled = true;
    emitStopTyping();

    try {
      const msgObj = { type: 'text', text };
      const payload = buildPayload(msgObj);
      const key = await getSharedKey(activeChat);
      const { ciphertext, iv } = await VaultCrypto.encrypt(key, payload);

      socket.emit('encrypted-message', { to: activeChat, ciphertext, iv });

      const ts = Date.now();
      if (!chatMessages[activeChat]) chatMessages[activeChat] = [];
      chatMessages[activeChat].push({ from: myUsername, ...msgObj, timestamp: ts });
      appendMessageEl({ from: myUsername, ...msgObj, timestamp: ts });
      scrollToBottom();
      renderContacts();
    } catch (err) { console.error('Send failed:', err); }

    sendBtn.disabled = false;
    msgInput.focus();
  }

  // ═══ SEND MEDIA FILE ══════════════════════════════════════════
  async function onFileSelected() {
    const file = fileInput.files[0];
    fileInput.value = '';
    if (!file || !activeChat) return;

    if (file.size > MAX_FILE_SIZE) {
      alert(`File too large. Maximum size is ${formatFileSize(MAX_FILE_SIZE)}.`);
      return;
    }

    try {
      const arrayBuf = await file.arrayBuffer();
      const bytes = new Uint8Array(arrayBuf);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      const b64data = btoa(binary);

      const msgObj = { type: 'media', name: file.name, mime: file.type || 'application/octet-stream', data: b64data, size: file.size };
      const payload = buildPayload(msgObj);
      const key = await getSharedKey(activeChat);
      const { ciphertext, iv } = await VaultCrypto.encrypt(key, payload);

      socket.emit('encrypted-message', { to: activeChat, ciphertext, iv });

      const ts = Date.now();
      if (!chatMessages[activeChat]) chatMessages[activeChat] = [];
      chatMessages[activeChat].push({ from: myUsername, ...msgObj, timestamp: ts });
      appendMessageEl({ from: myUsername, ...msgObj, timestamp: ts });
      scrollToBottom();
      renderContacts();
    } catch (err) { console.error('Media send failed:', err); }
  }

  // ═══ TYPING INDICATORS (FIXED) ════════════════════════════════
  function onMessageInput() {
    sendBtn.disabled = !msgInput.value.trim();
    if (!activeChat) return;

    if (!isSendingTyping) {
      isSendingTyping = true;
      socket.emit('typing', { to: activeChat });
    }

    clearTimeout(myTypingTimer);
    myTypingTimer = setTimeout(() => { emitStopTyping(); }, 2000);
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
    typingInd.classList.remove('hidden');
    scrollToBottom();
    clearTimeout(typingTimers[from]);
    typingTimers[from] = setTimeout(() => hideTyping(), 3000);
  }

  function hideTyping() {
    typingInd.classList.add('hidden');
  }

  // ═══ KEY MANAGEMENT ════════════════════════════════════════════
  async function getSharedKey(username) {
    if (sharedKeys[username]) return sharedKeys[username];
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
  function emitAsync(ev, data) {
    return new Promise(r => socket.emit(ev, data, r));
  }
  function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
  function truncate(s, n) { return s.length > n ? s.slice(0, n) + '…' : s; }
  function formatTime(ts) { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }); }
  function formatDate(ts) {
    const d = new Date(ts), today = new Date(), yday = new Date(today);
    yday.setDate(today.getDate() - 1);
    if (d.toDateString() === today.toDateString()) return 'Today';
    if (d.toDateString() === yday.toDateString()) return 'Yesterday';
    return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' });
  }
  function formatFileSize(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
  }
  function showError(msg) { loginError.textContent = msg; loginError.hidden = false; }
  function hideError() { loginError.hidden = true; }

  // ═══ LOGOUT ════════════════════════════════════════════════════
  window._vaultLogout = function () {
    endCall();
    localStorage.removeItem('vault_username');
    if (socket) { socket.disconnect(); socket = null; }
    myUsername = null; myKeyPair = null; myPublicJwk = null;
    activeChat = null; sharedKeys = {}; contacts = [];
    chatMessages = {}; unreadCounts = {};
    chatView.classList.remove('active');
    loginView.classList.add('active');
    usernameInput.value = '';
    loginBtn.querySelector('.btn-text').textContent = 'Connect Securely';
    loginBtn.disabled = true;
  };

  // ═══ WEBRTC VOICE/VIDEO CALLS (E2EE via DTLS-SRTP) ════════════
  const ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
  ];

  let peerConnection = null;
  let localStream    = null;
  let callPeer       = null;
  let callType       = null;   // 'voice' | 'video'
  let callTimerInt   = null;
  let callSeconds    = 0;
  let isMuted        = false;
  let isCamOff       = false;
  let pendingOffer   = null;

  const incomingEl   = $('#incoming-call');
  const activeCallEl = $('#active-call');
  const remoteVideo  = $('#remote-video');
  const localVideo   = $('#local-video');
  const voiceCallBtn = $('#voice-call-btn');
  const videoCallBtn = $('#video-call-btn');
  const acceptCallBtn= $('#accept-call');
  const rejectCallBtn= $('#reject-call');
  const endCallBtn   = $('#end-call');
  const toggleMuteBtn= $('#toggle-mute');
  const toggleCamBtn = $('#toggle-camera');
  const callTimerEl  = $('#call-timer');
  const callPeerName = $('#call-peer-name');

  voiceCallBtn.addEventListener('click', () => startCall('voice'));
  videoCallBtn.addEventListener('click', () => startCall('video'));
  acceptCallBtn.addEventListener('click', acceptCall);
  rejectCallBtn.addEventListener('click', rejectCall);
  endCallBtn.addEventListener('click', () => { socket.emit('call-end', { to: callPeer }); endCall(); });
  toggleMuteBtn.addEventListener('click', toggleMute);
  toggleCamBtn.addEventListener('click', toggleCamera);

  // ── Start outgoing call ──────────────────────────────────────────
  async function startCall(type) {
    if (!activeChat || peerConnection) return;
    const c = contacts.find(u => u.username === activeChat);
    if (!c?.online) return alert('User is offline');

    callPeer = activeChat;
    callType = type;

    try {
      localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: type === 'video',
      });
    } catch (err) {
      alert('Could not access microphone/camera: ' + err.message);
      return;
    }

    setupPeerConnection();
    localStream.getTracks().forEach(t => peerConnection.addTrack(t, localStream));

    const offer = await peerConnection.createOffer();
    await peerConnection.setLocalDescription(offer);

    socket.emit('call-offer', { to: callPeer, offer, callType: type });
    showActiveCall();
  }

  // ── Receive incoming call ────────────────────────────────────────
  function onCallOffer(data) {
    if (peerConnection) {
      socket.emit('call-reject', { to: data.from });
      return;
    }
    pendingOffer = data;
    callPeer = data.from;
    callType = data.callType;

    $('#incoming-avatar').textContent = data.from[0].toUpperCase();
    $('#incoming-name').textContent = data.from;
    $('#incoming-type').textContent = `Incoming ${data.callType} call…`;
    incomingEl.classList.remove('hidden');
  }

  async function acceptCall() {
    incomingEl.classList.add('hidden');
    if (!pendingOffer) return;

    try {
      localStream = await navigator.mediaDevices.getUserMedia({
        audio: true,
        video: callType === 'video',
      });
    } catch (err) {
      alert('Could not access microphone/camera: ' + err.message);
      socket.emit('call-reject', { to: callPeer });
      pendingOffer = null;
      return;
    }

    setupPeerConnection();
    localStream.getTracks().forEach(t => peerConnection.addTrack(t, localStream));

    await peerConnection.setRemoteDescription(new RTCSessionDescription(pendingOffer.offer));
    const answer = await peerConnection.createAnswer();
    await peerConnection.setLocalDescription(answer);

    socket.emit('call-answer', { to: callPeer, answer });
    pendingOffer = null;
    showActiveCall();
  }

  function rejectCall() {
    incomingEl.classList.add('hidden');
    if (callPeer) socket.emit('call-reject', { to: callPeer });
    pendingOffer = null;
    callPeer = null;
  }

  // ── Peer connection setup ────────────────────────────────────────
  function setupPeerConnection() {
    peerConnection = new RTCPeerConnection({ iceServers: ICE_SERVERS });

    peerConnection.onicecandidate = (e) => {
      if (e.candidate) socket.emit('ice-candidate', { to: callPeer, candidate: e.candidate });
    };

    peerConnection.ontrack = (e) => {
      remoteVideo.srcObject = e.streams[0];
    };

    peerConnection.onconnectionstatechange = () => {
      if (['disconnected', 'failed', 'closed'].includes(peerConnection?.connectionState)) {
        endCall();
      }
    };
  }

  // ── Show/hide call UI ────────────────────────────────────────────
  function showActiveCall() {
    callPeerName.textContent = callPeer;
    localVideo.srcObject = localStream;
    localVideo.style.display = callType === 'video' ? 'block' : 'none';
    activeCallEl.classList.remove('hidden');
    callSeconds = 0;
    callTimerEl.textContent = '00:00';
    callTimerInt = setInterval(() => {
      callSeconds++;
      const m = String(Math.floor(callSeconds / 60)).padStart(2, '0');
      const s = String(callSeconds % 60).padStart(2, '0');
      callTimerEl.textContent = `${m}:${s}`;
    }, 1000);
    isMuted = false; isCamOff = false;
    toggleMuteBtn.classList.remove('active');
    toggleCamBtn.classList.remove('active');
  }

  function endCall() {
    activeCallEl.classList.add('hidden');
    incomingEl.classList.add('hidden');
    clearInterval(callTimerInt);
    if (localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
    if (peerConnection) { peerConnection.close(); peerConnection = null; }
    remoteVideo.srcObject = null;
    localVideo.srcObject = null;
    callPeer = null; pendingOffer = null;
  }

  // ── Call controls ────────────────────────────────────────────────
  function toggleMute() {
    if (!localStream) return;
    isMuted = !isMuted;
    localStream.getAudioTracks().forEach(t => t.enabled = !isMuted);
    toggleMuteBtn.classList.toggle('active', isMuted);
  }

  function toggleCamera() {
    if (!localStream) return;
    isCamOff = !isCamOff;
    localStream.getVideoTracks().forEach(t => t.enabled = !isCamOff);
    toggleCamBtn.classList.toggle('active', isCamOff);
  }

  // ── Bind call socket events (called inside bindSocketEvents) ────
  const _origBind = bindSocketEvents;
  bindSocketEvents = function () {
    _origBind();

    socket.on('call-offer', onCallOffer);

    socket.on('call-answer', async ({ from, answer }) => {
      if (peerConnection) {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(answer));
      }
    });

    socket.on('ice-candidate', async ({ from, candidate }) => {
      if (peerConnection && candidate) {
        try { await peerConnection.addIceCandidate(new RTCIceCandidate(candidate)); }
        catch (e) { console.warn('ICE error:', e); }
      }
    });

    socket.on('call-rejected', ({ from, reason }) => {
      endCall();
      alert(reason || `${from} declined the call.`);
    });

    socket.on('call-ended', ({ from }) => {
      endCall();
    });
  };

})();
