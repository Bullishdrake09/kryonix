/**
 * Kryonix — Messages Routes
 * Server stores ONLY ciphertext — never decrypts
 */
'use strict';

const express = require('express');
const { v4: uuidv4 }    = require('uuid');
const { getDB }          = require('../db/database');
const { requireAuth }    = require('../middleware/auth');
const { validate, schemas } = require('../middleware/validate');
const router = express.Router();

router.use(requireAuth);

// POST /api/messages — store encrypted message
router.post('/', validate(schemas.sendMessage), async (req, res) => {
  const db = getDB();
  const { conversationId, ciphertext, iv, ephemeralKey, msgNumber, type, fileRef } = req.body;

  // Verify sender is a member of the conversation
  const membership = await db('conversation_members')
    .where({ conversation_id: conversationId, user_id: req.user.userId }).first();
  if (!membership) return res.status(403).json({ error: 'Not a member of this conversation' });

  const msgId = uuidv4();
  await db('messages').insert({
    id:              msgId,
    conversation_id: conversationId,
    sender_id:       req.user.userId,
    type:            type || 'text',
    ciphertext,
    iv,
    ephemeral_key:   ephemeralKey,
    message_number:  String(msgNumber || 0),
    file_name:       fileRef?.name,
    file_size:       fileRef?.size,
    file_mime:       fileRef?.mime,
    file_storage_key:fileRef?.storageKey,
    expires_at:      fileRef?.expiresAt || null,
  });

  res.status(201).json({ id: msgId, ts: new Date().toISOString() });
});

// GET /api/messages/:conversationId — fetch ciphertexts for a conversation
router.get('/:conversationId', async (req, res) => {
  const db = getDB();
  const { conversationId } = req.params;
  const limit  = Math.min(parseInt(req.query.limit)  || 50, 200);
  const before = req.query.before; // cursor-based pagination

  const membership = await db('conversation_members')
    .where({ conversation_id: conversationId, user_id: req.user.userId }).first();
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  let query = db('messages')
    .where({ conversation_id: conversationId })
    .orderBy('created_at', 'desc')
    .limit(limit)
    .select('id','sender_id','type','ciphertext','iv','ephemeral_key','message_number',
            'file_name','file_size','file_mime','delivered','read','created_at');

  if (before) query = query.where('created_at', '<', before);

  const msgs = await query;
  res.json(msgs.reverse());
});

// PUT /api/messages/:id/read
router.put('/:id/read', async (req, res) => {
  const db = getDB();
  await db('messages')
    .where({ id: req.params.id })
    .update({ read: true, read_at: new Date() });
  res.json({ ok: true });
});

// DELETE /api/messages/:id — only sender can delete
router.delete('/:id', async (req, res) => {
  const db  = getDB();
  const msg = await db('messages').where({ id: req.params.id }).first();
  if (!msg) return res.status(404).json({ error: 'Not found' });
  if (msg.sender_id !== req.user.userId) return res.status(403).json({ error: 'Forbidden' });
  await db('messages').where({ id: req.params.id }).delete();
  res.json({ ok: true });
});

// POST /api/messages/:id/react
router.post('/:id/react', async (req, res) => {
  const db    = getDB();
  const { emoji } = req.body;
  if (!emoji) return res.status(400).json({ error: 'Missing emoji' });
  const existing = await db('message_reactions')
    .where({ message_id: req.params.id, user_id: req.user.userId, emoji }).first();
  if (existing) {
    await db('message_reactions').where({ id: existing.id }).delete();
    return res.json({ action: 'removed' });
  }
  await db('message_reactions').insert({
    id: uuidv4(), message_id: req.params.id, user_id: req.user.userId, emoji,
  });
  res.json({ action: 'added' });
});

module.exports = router;
