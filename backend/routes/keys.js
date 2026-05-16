/**
 * Kryonix — Key Management Routes
 */
'use strict';

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const {
  storeKeyBundle, fetchPrekeyBundle,
  replenishPrekeys, getPrekeyCount,
} = require('../crypto/keyManager');
const router = express.Router();

router.use(requireAuth);

// POST /api/keys/bundle — upload initial key bundle
router.post('/bundle', async (req, res) => {
  try {
    await storeKeyBundle(req.user.userId, req.body);
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// GET /api/keys/bundle/:userId — fetch prekey bundle for X3DH session init
router.get('/bundle/:userId', async (req, res) => {
  try {
    const bundle = await fetchPrekeyBundle(req.params.userId);
    res.json(bundle);
  } catch (err) {
    res.status(404).json({ error: err.message });
  }
});

// POST /api/keys/prekeys — replenish one-time prekeys
router.post('/prekeys', async (req, res) => {
  const { prekeys } = req.body;
  if (!Array.isArray(prekeys) || !prekeys.length)
    return res.status(400).json({ error: 'prekeys array required' });
  await replenishPrekeys(req.user.userId, prekeys);
  res.json({ ok: true, count: prekeys.length });
});

// GET /api/keys/prekeys/count — check remaining OTPK count
router.get('/prekeys/count', async (req, res) => {
  const count = await getPrekeyCount(req.user.userId);
  res.json({ count, needsReplenishment: count < 10 });
});

module.exports = router;
