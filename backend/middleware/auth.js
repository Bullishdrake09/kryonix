/**
 * Kryonix — Auth Middleware
 */
'use strict';

const { verifyToken } = require('../services/jwt');
const { logger }      = require('../services/logger');

async function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing Authorization header' });
  }
  const token = header.slice(7);
  try {
    req.user = await verifyToken(token);
    next();
  } catch (err) {
    logger.warn(`Auth failed [${req.id}]: ${err.message}`);
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (roles.length && !roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
}

module.exports = { requireAuth, requireRole };
