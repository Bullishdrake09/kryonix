/**
 * Kryonix — WebSocket Signaling Service
 * Handles WebRTC SDP/ICE exchange, presence, typing indicators
 * All media is DTLS-SRTP encrypted peer-to-peer — server only relays signaling
 */
'use strict';

const { v4: uuidv4 } = require('uuid');
const { logger } = require('./logger');

const MSG = {
  // Auth
  AUTH:        'auth',
  AUTH_OK:     'auth_ok',
  AUTH_FAIL:   'auth_fail',
  // Presence
  PRESENCE:    'presence',
  USER_ONLINE: 'user_online',
  USER_OFFLINE:'user_offline',
  // Messaging
  MESSAGE:     'message',
  MESSAGE_ACK: 'message_ack',
  DELIVERED:   'delivered',
  READ:        'read',
  TYPING:      'typing',
  TYPING_STOP: 'typing_stop',
  // WebRTC signaling
  CALL_OFFER:     'call_offer',
  CALL_ANSWER:    'call_answer',
  CALL_REJECT:    'call_reject',
  CALL_END:       'call_end',
  ICE_CANDIDATE:  'ice_candidate',
  CALL_RINGING:   'call_ringing',
  // Keys
  KEY_UPDATE:     'key_update',
  PREKEY_REQUEST: 'prekey_request',
  PREKEY_BUNDLE:  'prekey_bundle',
  // Errors
  ERROR:          'error',
  PING:           'ping',
  PONG:           'pong',
};

class SignalingService {
  constructor(wss, verifyToken) {
    this.wss         = wss;
    this.verifyToken = verifyToken;
    this.clients     = new Map();   // userId -> Set<WebSocket>
    this.sockets     = new Map();   // ws -> { userId, deviceId, connectedAt }
    this.typingTimers= new Map();   // `${from}-${to}` -> timer

    wss.on('connection', (ws, req) => this._onConnect(ws, req));
    logger.info('WebSocket signaling service initialized');
  }

  // ── CONNECTION ─────────────────────────────────────────────
  _onConnect(ws, req) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    logger.info(`WS connection from ${ip}`);

    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });
    ws.on('message', data => this._onMessage(ws, data));
    ws.on('close',   ()   => this._onClose(ws));
    ws.on('error',   err  => logger.error('WS error:', err.message));

    // Require auth within 10s
    ws._authTimeout = setTimeout(() => {
      if (!this.sockets.has(ws)) {
        ws.close(4001, 'Authentication timeout');
      }
    }, 10000);
  }

  // ── MESSAGE ROUTER ─────────────────────────────────────────
  _onMessage(ws, data) {
    let msg;
    try {
      msg = JSON.parse(data);
    } catch {
      this._send(ws, { type: MSG.ERROR, error: 'Invalid JSON' });
      return;
    }

    if (!msg.type) {
      this._send(ws, { type: MSG.ERROR, error: 'Missing message type' });
      return;
    }

    // Auth gate
    if (msg.type !== MSG.AUTH && !this.sockets.has(ws)) {
      this._send(ws, { type: MSG.ERROR, error: 'Not authenticated' });
      return;
    }

    switch (msg.type) {
      case MSG.AUTH:           return this._handleAuth(ws, msg);
      case MSG.PING:           return this._send(ws, { type: MSG.PONG, ts: Date.now() });
      case MSG.MESSAGE:        return this._handleMessage(ws, msg);
      case MSG.READ:           return this._handleRead(ws, msg);
      case MSG.TYPING:         return this._handleTyping(ws, msg, true);
      case MSG.TYPING_STOP:    return this._handleTyping(ws, msg, false);
      case MSG.CALL_OFFER:     return this._relay(ws, msg, msg.to);
      case MSG.CALL_ANSWER:    return this._relay(ws, msg, msg.to);
      case MSG.CALL_REJECT:    return this._relay(ws, msg, msg.to);
      case MSG.CALL_END:       return this._relay(ws, msg, msg.to);
      case MSG.ICE_CANDIDATE:  return this._relay(ws, msg, msg.to);
      case MSG.KEY_UPDATE:     return this._handleKeyUpdate(ws, msg);
      case MSG.PREKEY_REQUEST: return this._handlePrekeyRequest(ws, msg);
      default:
        this._send(ws, { type: MSG.ERROR, error: `Unknown type: ${msg.type}` });
    }
  }

  // ── AUTH ───────────────────────────────────────────────────
  async _handleAuth(ws, msg) {
    clearTimeout(ws._authTimeout);
    try {
      const payload = await this.verifyToken(msg.token);
      const { userId, deviceId = uuidv4() } = payload;

      // Register socket
      this.sockets.set(ws, { userId, deviceId, connectedAt: Date.now() });
      if (!this.clients.has(userId)) this.clients.set(userId, new Set());
      this.clients.get(userId).add(ws);

      this._send(ws, { type: MSG.AUTH_OK, userId, deviceId });
      logger.info(`WS authenticated: user=${userId} device=${deviceId}`);

      // Broadcast online presence
      this._broadcastPresence(userId, true);
    } catch (err) {
      logger.warn(`WS auth failed: ${err.message}`);
      this._send(ws, { type: MSG.AUTH_FAIL, error: 'Invalid token' });
      ws.close(4002, 'Authentication failed');
    }
  }

  // ── CLOSE ──────────────────────────────────────────────────
  _onClose(ws) {
    const meta = this.sockets.get(ws);
    if (!meta) return;
    const { userId } = meta;
    this.sockets.delete(ws);
    const userSockets = this.clients.get(userId);
    if (userSockets) {
      userSockets.delete(ws);
      if (userSockets.size === 0) {
        this.clients.delete(userId);
        this._broadcastPresence(userId, false);
        logger.info(`User offline: ${userId}`);
      }
    }
  }

  // ── MESSAGE RELAY ──────────────────────────────────────────
  _handleMessage(ws, msg) {
    const { userId } = this.sockets.get(ws);
    const outbound = {
      type:    MSG.MESSAGE,
      id:      msg.id || uuidv4(),
      from:    userId,
      to:      msg.to,
      convoId: msg.convoId,
      // Only ciphertext and IV — server never sees plaintext
      ciphertext:   msg.ciphertext,
      iv:           msg.iv,
      ephemeralKey: msg.ephemeralKey,
      msgNumber:    msg.msgNumber,
      fileRef:      msg.fileRef,    // encrypted file reference if applicable
      ts:           Date.now(),
    };

    // ACK to sender
    this._send(ws, { type: MSG.MESSAGE_ACK, id: outbound.id, ts: outbound.ts });

    // Deliver to recipient(s)
    const delivered = this._sendToUser(msg.to, outbound);
    if (delivered) {
      this._sendToUser(userId, { type: MSG.DELIVERED, id: outbound.id, ts: Date.now() });
    }
  }

  _handleRead(ws, msg) {
    const { userId } = this.sockets.get(ws);
    this._sendToUser(msg.from, { type: MSG.READ, id: msg.id, readBy: userId, ts: Date.now() });
  }

  // ── TYPING ────────────────────────────────────────────────
  _handleTyping(ws, msg, isTyping) {
    const { userId } = this.sockets.get(ws);
    const key = `${userId}-${msg.to}`;
    clearTimeout(this.typingTimers.get(key));
    if (isTyping) {
      this._sendToUser(msg.to, { type: MSG.TYPING, from: userId, convoId: msg.convoId });
      // Auto-stop after 5s
      this.typingTimers.set(key, setTimeout(() => {
        this._sendToUser(msg.to, { type: MSG.TYPING_STOP, from: userId });
        this.typingTimers.delete(key);
      }, 5000));
    } else {
      this._sendToUser(msg.to, { type: MSG.TYPING_STOP, from: userId });
      this.typingTimers.delete(key);
    }
  }

  // ── KEY MANAGEMENT ────────────────────────────────────────
  _handleKeyUpdate(ws, msg) {
    // When a user rotates their prekeys, notify contacts
    const { userId } = this.sockets.get(ws);
    logger.info(`Key update from ${userId}`);
    // In production: persist to DB and notify active conversations
    this._send(ws, { type: MSG.MESSAGE_ACK, id: msg.id, ts: Date.now() });
  }

  _handlePrekeyRequest(ws, msg) {
    // Fetch a one-time prekey bundle for target user from DB
    // In production: query key_bundles table
    const { userId } = this.sockets.get(ws);
    logger.info(`Prekey request: ${userId} -> ${msg.targetUserId}`);
    // Relay prekey bundle back (placeholder — real impl fetches from DB)
    this._send(ws, {
      type: MSG.PREKEY_BUNDLE,
      targetUserId: msg.targetUserId,
      bundle: msg.cachedBundle || null,
    });
  }

  // ── PRESENCE ─────────────────────────────────────────────
  _broadcastPresence(userId, online) {
    const type = online ? MSG.USER_ONLINE : MSG.USER_OFFLINE;
    const payload = { type, userId, ts: Date.now() };
    // Broadcast to all connected users (in production: only to contacts)
    this.sockets.forEach((meta, ws) => {
      if (meta.userId !== userId) this._send(ws, payload);
    });
  }

  // ── GENERIC RELAY ────────────────────────────────────────
  _relay(ws, msg, targetUserId) {
    if (!targetUserId) {
      this._send(ws, { type: MSG.ERROR, error: 'Missing target userId' });
      return;
    }
    const { userId } = this.sockets.get(ws);
    this._sendToUser(targetUserId, { ...msg, from: userId });
  }

  // ── SEND HELPERS ─────────────────────────────────────────
  _send(ws, payload) {
    if (ws.readyState === ws.OPEN) {
      try { ws.send(JSON.stringify(payload)); }
      catch (e) { logger.error('WS send error:', e.message); }
    }
  }

  _sendToUser(userId, payload) {
    const sockets = this.clients.get(userId);
    if (!sockets || sockets.size === 0) return false;
    sockets.forEach(ws => this._send(ws, payload));
    return true;
  }

  // ── HEARTBEAT ────────────────────────────────────────────
  startHeartbeat(interval = 30000) {
    setInterval(() => {
      this.wss.clients.forEach(ws => {
        if (!ws.isAlive) { ws.terminate(); return; }
        ws.isAlive = false;
        ws.ping();
      });
    }, interval);
  }

  // ── STATS ────────────────────────────────────────────────
  getStats() {
    return {
      totalConnections:  this.wss.clients.size,
      authenticatedUsers: this.clients.size,
      sockets: this.sockets.size,
    };
  }
}

module.exports = SignalingService;
