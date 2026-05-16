/**
 * Kryonix — User Routes
 */
'use strict';

const express = require('express');
const { getDB } = require('../db/database');
const { requireAuth } = require('../middleware/auth');
const router = express.Router();

router.use(requireAuth);

// GET /api/users/me
router.get('/me', async (req, res) => {
  const db   = getDB();
  const user = await db('users').where({ id: req.user.userId })
    .select('id','username','display_name','avatar_class','status','online','last_seen').first();
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// GET /api/users/search?q=
router.get('/search', async (req, res) => {
  const db = getDB();
  const q  = (req.query.q || '').trim();
  if (q.length < 2) return res.json([]);
  const users = await db('users')
    .where('username','like',`%${q}%`)
    .orWhere('display_name','like',`%${q}%`)
    .whereNot({ id: req.user.userId })
    .select('id','username','display_name','avatar_class','online','last_seen')
    .limit(20);
  res.json(users);
});

// PUT /api/users/me
router.put('/me', async (req, res) => {
  const db = getDB();
  const { displayName, status, avatarClass } = req.body;
  const updates = {};
  if (displayName) updates.display_name = displayName.slice(0,64);
  if (status)      updates.status       = status.slice(0,128);
  if (avatarClass) updates.avatar_class = avatarClass;
  await db('users').where({ id: req.user.userId }).update(updates);
  res.json({ message: 'Profile updated' });
});

// GET /api/users/:id/keys — fetch prekey bundle for X3DH
router.get('/:id/keys', async (req, res) => {
  const { fetchPrekeyBundle } = require('../crypto/keyManager');
  try {
    const bundle = await fetchPrekeyBundle(req.params.id);
    res.json(bundle);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

module.exports = router;
