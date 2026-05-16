/**
 * Kryonix — Database Layer
 * SQLite (dev) / PostgreSQL (prod) via knex
 * Zero plaintext storage: all message content is E2EE ciphertext
 */

'use strict';

const knex   = require('knex');
const path   = require('path');
const { logger } = require('../services/logger');

let db;

const config = {
  development: {
    client: 'sqlite3',
    connection: { filename: path.join(__dirname, '../../kryonix.sqlite3') },
    useNullAsDefault: true,
    pool: { min: 1, max: 5 },
  },
  production: {
    client: 'pg',
    connection: {
      host:     process.env.DB_HOST     || 'localhost',
      port:     parseInt(process.env.DB_PORT) || 5432,
      database: process.env.DB_NAME     || 'kryonix',
      user:     process.env.DB_USER     || 'kryonix',
      password: process.env.DB_PASSWORD || '',
      ssl:      process.env.DB_SSL === 'true' ? { rejectUnauthorized: true } : false,
    },
    pool: { min: 2, max: 20 },
  },
};

async function initDB() {
  const env = process.env.NODE_ENV || 'development';
  db = knex(config[env] || config.development);

  // Test connection
  await db.raw('SELECT 1');
  logger.info(`Database connected [${env}]`);

  // Run migrations inline
  await runMigrations();
  return db;
}

async function runMigrations() {
  const exists = await db.schema.hasTable('users');
  if (exists) return;

  logger.info('Running initial migrations…');

  await db.schema.createTable('users', t => {
    t.string('id').primary();
    t.string('username').unique().notNullable();
    t.string('display_name').notNullable();
    t.string('password_hash').notNullable();       // bcrypt
    t.string('ecdh_public_key').notNullable();      // ECDH P-256 raw hex
    t.string('signed_prekey').notNullable();        // X3DH signed prekey
    t.string('signed_prekey_sig').notNullable();    // Ed25519 signature
    t.string('identity_key').notNullable();         // Ed25519 identity key (public)
    t.text('prekey_bundle');                        // JSON: one-time prekeys
    t.string('avatar_class').defaultTo('av-green');
    t.string('status').defaultTo('Available');
    t.boolean('online').defaultTo(false);
    t.timestamp('last_seen').defaultTo(db.fn.now());
    t.timestamps(true, true);
  });

  await db.schema.createTable('sessions', t => {
    t.string('id').primary();
    t.string('user_id').references('id').inTable('users').onDelete('CASCADE');
    t.string('token_hash').notNullable();           // SHA-256 of JWT
    t.string('device_id').notNullable();
    t.string('ip_address');
    t.string('user_agent');
    t.timestamp('expires_at').notNullable();
    t.timestamps(true, true);
  });

  await db.schema.createTable('contacts', t => {
    t.string('id').primary();
    t.string('user_id').references('id').inTable('users').onDelete('CASCADE');
    t.string('contact_user_id').references('id').inTable('users').onDelete('CASCADE');
    t.boolean('verified').defaultTo(false);         // safety number verified
    t.string('verification_ts');
    t.timestamps(true, true);
    t.unique(['user_id', 'contact_user_id']);
  });

  await db.schema.createTable('conversations', t => {
    t.string('id').primary();
    t.string('type').defaultTo('dm');               // dm | group
    t.string('name');                               // for groups
    t.string('mls_group_id');                       // MLS group identifier
    t.timestamps(true, true);
  });

  await db.schema.createTable('conversation_members', t => {
    t.string('id').primary();
    t.string('conversation_id').references('id').inTable('conversations').onDelete('CASCADE');
    t.string('user_id').references('id').inTable('users').onDelete('CASCADE');
    t.string('role').defaultTo('member');           // member | admin
    t.timestamps(true, true);
    t.unique(['conversation_id', 'user_id']);
  });

  // Messages store ONLY ciphertext — server never sees plaintext
  await db.schema.createTable('messages', t => {
    t.string('id').primary();
    t.string('conversation_id').references('id').inTable('conversations').onDelete('CASCADE');
    t.string('sender_id').references('id').inTable('users').onDelete('SET NULL').nullable();
    t.string('type').defaultTo('text');             // text | file | system | call
    // E2EE ciphertext fields (AES-256-GCM)
    t.text('ciphertext');                           // hex-encoded ciphertext
    t.string('iv');                                 // hex-encoded IV
    t.string('ephemeral_key');                      // for X3DH sessions
    t.string('message_number').defaultTo('0');      // Double Ratchet counter
    // File metadata (not encrypted — just references)
    t.string('file_name');
    t.string('file_size');
    t.string('file_mime');
    t.string('file_storage_key');                   // encrypted storage reference
    // Delivery
    t.boolean('delivered').defaultTo(false);
    t.timestamp('delivered_at');
    t.boolean('read').defaultTo(false);
    t.timestamp('read_at');
    // Expiry (optional retention policy)
    t.timestamp('expires_at').nullable();
    t.timestamps(true, true);
  });

  await db.schema.createTable('message_reactions', t => {
    t.string('id').primary();
    t.string('message_id').references('id').inTable('messages').onDelete('CASCADE');
    t.string('user_id').references('id').inTable('users').onDelete('CASCADE');
    t.string('emoji').notNullable();
    t.timestamps(true, true);
    t.unique(['message_id', 'user_id', 'emoji']);
  });

  // Public keys only — never private keys
  await db.schema.createTable('key_bundles', t => {
    t.string('id').primary();
    t.string('user_id').references('id').inTable('users').onDelete('CASCADE');
    t.string('key_type').notNullable();             // identity | signed_prekey | one_time_prekey
    t.text('public_key').notNullable();             // hex-encoded public key
    t.string('key_id').notNullable();
    t.string('signature');                          // Ed25519 signature for signed prekeys
    t.boolean('used').defaultTo(false);             // one-time prekeys get consumed
    t.timestamps(true, true);
  });

  // WebRTC call records
  await db.schema.createTable('call_records', t => {
    t.string('id').primary();
    t.string('conversation_id').references('id').inTable('conversations');
    t.string('initiator_id').references('id').inTable('users');
    t.string('type').notNullable();                 // voice | video
    t.string('status').defaultTo('initiated');      // initiated | answered | missed | ended
    t.integer('duration_seconds').defaultTo(0);
    t.timestamp('started_at').defaultTo(db.fn.now());
    t.timestamp('ended_at').nullable();
    t.timestamps(true, true);
  });

  logger.info('Migrations complete');
}

function getDB() {
  if (!db) throw new Error('Database not initialized. Call initDB() first.');
  return db;
}

module.exports = { initDB, getDB };
