/**
 * Kryonix — Auth Routes
 * POST /api/auth/register
 * POST /api/auth/login
 * POST /api/auth/refresh
 * POST /api/auth/logout
 */
'use strict';

const express  = require('express');
const bcrypt   = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const { getDB }       = require('../db/database');
const { signAccess, signRefresh, verifyRefresh, hashToken } = require('../services/jwt');
const { storeKeyBundle } = require('../crypto/keyManager');
const { requireAuth }    = require('../middleware/auth');
const { validate, schemas } = require('../middleware/validate');
const { logger } = require('../services/logger');

const router = express.Router();
const BCRYPT_ROUNDS = 12;

// ── REGISTER ──────────────────────────────────────────────────
router.post('/register', validate(schemas.register), async (req, res) => {
  const db = getDB();
  const { username, displayName, password, keyBundle } = req.body;

  try {
    const existing = await db('users').where({ username }).first();
    if (existing) return res.status(409).json({ error: 'Username already taken' });

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const userId = uuidv4();

    await db('users').insert({
      id:             userId,
      username,
      display_name:   displayName,
      password_hash:  passwordHash,
      ecdh_public_key:      keyBundle.identityKey,
      signed_prekey:        keyBundle.signedPrekey,
      signed_prekey_sig:    keyBundle.signedPrekeySignature,
      identity_key:         keyBundle.identityKey,
    });

    await storeKeyBundle(userId, keyBundle);

    const accessToken  = signAccess({ userId, username, role: 'user' });
    const refreshToken = signRefresh({ userId, username });

    await db('sessions').insert({
      id:          uuidv4(),
      user_id:     userId,
      token_hash:  hashToken(refreshToken),
      device_id:   req.body.deviceId || uuidv4(),
      ip_address:  req.ip,
      user_agent:  req.headers['user-agent'],
      expires_at:  new Date(Date.now() + 7 * 24 * 3600 * 1000),
    });

    logger.info(`New user registered: ${username} (${userId})`);
    res.status(201).json({ userId, accessToken, refreshToken, expiresIn: 900 });
  } catch (err) {
    logger.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ── LOGIN ─────────────────────────────────────────────────────
router.post('/login', validate(schemas.login), async (req, res) => {
  const db = getDB();
  const { username, password, deviceId } = req.body;

  try {
    const user = await db('users').where({ username }).first();
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    await db('users').where({ id: user.id }).update({ online: true, last_seen: new Date() });

    const accessToken  = signAccess({ userId: user.id, username, role: 'user' });
    const refreshToken = signRefresh({ userId: user.id, username });

    await db('sessions').insert({
      id:         uuidv4(),
      user_id:    user.id,
      token_hash: hashToken(refreshToken),
      device_id:  deviceId || uuidv4(),
      ip_address: req.ip,
      user_agent: req.headers['user-agent'],
      expires_at: new Date(Date.now() + 7 * 24 * 3600 * 1000),
    });

    logger.info(`Login: ${username}`);
    res.json({
      userId:       user.id,
      displayName:  user.display_name,
      avatarClass:  user.avatar_class,
      accessToken,
      refreshToken,
      expiresIn: 900,
    });
  } catch (err) {
    logger.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ── REFRESH ───────────────────────────────────────────────────
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Missing refresh token' });
  try {
    const db      = getDB();
    const payload = await verifyRefresh(refreshToken);
    const session = await db('sessions').where({ token_hash: hashToken(refreshToken) }).first();
    if (!session) return res.status(401).json({ error: 'Session not found or expired' });
    const accessToken = signAccess({ userId: payload.userId, username: payload.username, role: 'user' });
    res.json({ accessToken, expiresIn: 900 });
  } catch {
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// ── LOGOUT ────────────────────────────────────────────────────
router.post('/logout', requireAuth, async (req, res) => {
  const db = getDB();
  const { refreshToken } = req.body;
  if (refreshToken) {
    await db('sessions').where({ token_hash: hashToken(refreshToken), user_id: req.user.userId }).delete();
  }
  await db('users').where({ id: req.user.userId }).update({ online: false, last_seen: new Date() });
  res.json({ message: 'Logged out' });
});

module.exports = router;
