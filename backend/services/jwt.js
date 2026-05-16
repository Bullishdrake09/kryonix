/**
 * Kryonix — JWT Service
 * Short-lived access tokens + long-lived refresh tokens
 */
'use strict';

const jwt    = require('jsonwebtoken');
const crypto = require('crypto');

const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET  || crypto.randomBytes(64).toString('hex');
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || crypto.randomBytes(64).toString('hex');
const ACCESS_TTL     = process.env.JWT_ACCESS_TTL     || '15m';
const REFRESH_TTL    = process.env.JWT_REFRESH_TTL    || '7d';

function signAccess(payload) {
  return jwt.sign(payload, ACCESS_SECRET, {
    expiresIn: ACCESS_TTL,
    issuer:    'kryonix',
    audience:  'kryonix-client',
  });
}

function signRefresh(payload) {
  return jwt.sign(payload, REFRESH_SECRET, {
    expiresIn: REFRESH_TTL,
    issuer:    'kryonix',
    audience:  'kryonix-refresh',
  });
}

function verifyToken(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, ACCESS_SECRET, {
      issuer:   'kryonix',
      audience: 'kryonix-client',
    }, (err, decoded) => {
      if (err) reject(err);
      else resolve(decoded);
    });
  });
}

function verifyRefresh(token) {
  return new Promise((resolve, reject) => {
    jwt.verify(token, REFRESH_SECRET, {
      issuer:   'kryonix',
      audience: 'kryonix-refresh',
    }, (err, decoded) => {
      if (err) reject(err);
      else resolve(decoded);
    });
  });
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

module.exports = { signAccess, signRefresh, verifyToken, verifyRefresh, hashToken };
