/**
 * Kryonix — Server-Side Key Manager
 * Stores ONLY public keys and prekey bundles
 * NEVER stores, processes, or logs private keys
 * Implements X3DH prekey distribution per Signal Protocol spec
 */
'use strict';

const { v4: uuidv4 } = require('uuid');
const { getDB }       = require('../db/database');
const { logger }      = require('../services/logger');

/**
 * Store a user's public key bundle after registration
 * Keys come pre-generated from the client (Web Crypto API)
 */
async function storeKeyBundle(userId, bundle) {
  const db = getDB();
  const {
    identityKey,        // Ed25519 public key (hex)
    signedPrekey,       // ECDH P-256 public key (hex)
    signedPrekeyId,
    signedPrekeySignature, // Ed25519 signature over signedPrekey
    oneTimePrekeys = [], // Array of { id, publicKey }
  } = bundle;

  await db.transaction(async trx => {
    // Store identity key
    await trx('key_bundles').insert({
      id:         uuidv4(),
      user_id:    userId,
      key_type:   'identity',
      public_key: identityKey,
      key_id:     'identity',
    }).onConflict(['user_id', 'key_type', 'key_id']).merge();

    // Store signed prekey
    await trx('key_bundles').insert({
      id:         uuidv4(),
      user_id:    userId,
      key_type:   'signed_prekey',
      public_key: signedPrekey,
      key_id:     String(signedPrekeyId),
      signature:  signedPrekeySignature,
    }).onConflict(['user_id', 'key_type', 'key_id']).merge();

    // Store one-time prekeys
    for (const opk of oneTimePrekeys) {
      await trx('key_bundles').insert({
        id:         uuidv4(),
        user_id:    userId,
        key_type:   'one_time_prekey',
        public_key: opk.publicKey,
        key_id:     String(opk.id),
        used:       false,
      }).onConflict(['user_id', 'key_type', 'key_id']).ignore();
    }
  });

  logger.info(`Key bundle stored for user ${userId} (${oneTimePrekeys.length} OTPKs)`);
}

/**
 * Fetch a prekey bundle for initiating an X3DH session with a user
 * Consumes one one-time prekey (they can only be used once)
 */
async function fetchPrekeyBundle(targetUserId) {
  const db = getDB();

  const [identityKey, signedPrekey, oneTimePrekey] = await Promise.all([
    db('key_bundles').where({ user_id: targetUserId, key_type: 'identity' }).first(),
    db('key_bundles').where({ user_id: targetUserId, key_type: 'signed_prekey' }).orderBy('created_at','desc').first(),
    db('key_bundles').where({ user_id: targetUserId, key_type: 'one_time_prekey', used: false }).first(),
  ]);

  if (!identityKey || !signedPrekey) {
    throw new Error(`No key bundle found for user ${targetUserId}`);
  }

  // Mark one-time prekey as used (atomic)
  if (oneTimePrekey) {
    await db('key_bundles').where({ id: oneTimePrekey.id }).update({ used: true });
    // Warn if running low
    const remaining = await db('key_bundles')
      .where({ user_id: targetUserId, key_type: 'one_time_prekey', used: false })
      .count('id as count').first();
    if (remaining.count < 5) {
      logger.warn(`User ${targetUserId} has only ${remaining.count} OTPKs remaining`);
    }
  }

  return {
    userId:                targetUserId,
    identityKey:           identityKey.public_key,
    signedPrekey:          signedPrekey.public_key,
    signedPrekeyId:        signedPrekey.key_id,
    signedPrekeySignature: signedPrekey.signature,
    oneTimePrekey:         oneTimePrekey ? {
      id:        oneTimePrekey.key_id,
      publicKey: oneTimePrekey.public_key,
    } : null,
  };
}

/**
 * Replenish one-time prekeys from client upload
 */
async function replenishPrekeys(userId, newPrekeys) {
  const db = getDB();
  const rows = newPrekeys.map(opk => ({
    id:         uuidv4(),
    user_id:    userId,
    key_type:   'one_time_prekey',
    public_key: opk.publicKey,
    key_id:     String(opk.id),
    used:       false,
  }));
  await db('key_bundles').insert(rows).onConflict(['user_id','key_type','key_id']).ignore();
  logger.info(`Replenished ${rows.length} OTPKs for user ${userId}`);
}

/**
 * Get remaining OTPK count for a user
 */
async function getPrekeyCount(userId) {
  const db = getDB();
  const r = await db('key_bundles')
    .where({ user_id: userId, key_type: 'one_time_prekey', used: false })
    .count('id as count').first();
  return parseInt(r.count) || 0;
}

module.exports = { storeKeyBundle, fetchPrekeyBundle, replenishPrekeys, getPrekeyCount };
