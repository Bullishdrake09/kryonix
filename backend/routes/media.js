/**
 * Kryonix — Media / WebRTC Routes
 * TURN credential generation, call records
 */
'use strict';

const express  = require('express');
const crypto   = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { getDB }       = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

router.use(requireAuth);

const TURN_SECRET  = process.env.TURN_SECRET  || crypto.randomBytes(32).toString('hex');
const TURN_HOST    = process.env.TURN_HOST    || 'turn.yourdomain.com';
const TURN_TTL     = parseInt(process.env.TURN_TTL) || 86400;

// GET /api/media/turn-credentials
// Generate time-limited TURN credentials using HMAC-SHA1 (coturn-compatible)
router.get('/turn-credentials', (req, res) => {
  const timestamp = Math.floor(Date.now() / 1000) + TURN_TTL;
  const username  = `${timestamp}:${req.user.userId}`;
  const password  = crypto.createHmac('sha1', TURN_SECRET)
    .update(username).digest('base64');

  res.json({
    iceServers: [
      { urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] },
      {
        urls:       [`turn:${TURN_HOST}:3478`, `turns:${TURN_HOST}:5349`],
        username,
        credential: password,
      },
    ],
    ttl: TURN_TTL,
  });
});

// POST /api/media/calls — create call record
router.post('/calls', async (req, res) => {
  const db  = getDB();
  const { conversationId, type } = req.body;
  if (!conversationId || !['voice','video'].includes(type))
    return res.status(400).json({ error: 'Invalid call parameters' });
  const id = uuidv4();
  await db('call_records').insert({
    id, conversation_id: conversationId, initiator_id: req.user.userId, type, status: 'initiated',
  });
  res.status(201).json({ id });
});

// PUT /api/media/calls/:id — update call status
router.put('/calls/:id', async (req, res) => {
  const db = getDB();
  const { status, durationSeconds } = req.body;
  const updates = { status };
  if (status === 'ended') { updates.ended_at = new Date(); updates.duration_seconds = durationSeconds || 0; }
  if (status === 'answered') updates.started_at = new Date();
  await db('call_records').where({ id: req.params.id }).update(updates);
  res.json({ ok: true });
});

// GET /api/media/calls — call history
router.get('/calls', async (req, res) => {
  const db   = getDB();
  const calls = await db('call_records')
    .join('conversations','call_records.conversation_id','conversations.id')
    .where('call_records.initiator_id', req.user.userId)
    .orWhereRaw(`EXISTS (SELECT 1 FROM conversation_members WHERE conversation_id = call_records.conversation_id AND user_id = ?)`, [req.user.userId])
    .orderBy('call_records.started_at','desc')
    .limit(50)
    .select('call_records.*');
  res.json(calls);
});

module.exports = router;
