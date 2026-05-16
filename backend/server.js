/**
 * Kryonix — Backend Server
 * Express + WebSocket signaling + REST API
 * Architecture: Microservices-ready monolith
 */

'use strict';

const express       = require('express');
const http          = require('http');
const WebSocket     = require('ws');
const cors          = require('cors');
const helmet        = require('helmet');
const rateLimit     = require('express-rate-limit');
const compression   = require('compression');
const morgan        = require('morgan');
const path          = require('path');
const { v4: uuidv4} = require('uuid');

// Route imports
const authRoutes     = require('./routes/auth');
const userRoutes     = require('./routes/users');
const messageRoutes  = require('./routes/messages');
const mediaRoutes    = require('./routes/media');
const aiRoutes       = require('./routes/ai');
const keyRoutes      = require('./routes/keys');

// Service imports
const { verifyToken }  = require('./services/jwt');
const { initDB }       = require('./db/database');
const { logger }       = require('./services/logger');
const SignalingService = require('./services/signaling');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server, path: '/ws' });

const PORT = process.env.PORT || 3001;

// ── MIDDLEWARE ──────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'fonts.googleapis.com'],
      styleSrc:       ["'self'", "'unsafe-inline'", 'cdn.jsdelivr.net', 'fonts.googleapis.com'],
      fontSrc:        ["'self'", 'fonts.gstatic.com', 'cdn.jsdelivr.net'],
      connectSrc:     ["'self'", 'ws:', 'wss:', 'http://localhost:11434'],
      mediaSrc:       ["'self'", 'blob:'],
      workerSrc:      ["'self'", 'blob:'],
      imgSrc:         ["'self'", 'data:', 'blob:'],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(compression());
app.use(morgan('combined', { stream: { write: msg => logger.info(msg.trim()) } }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID'],
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request ID middleware
app.use((req, _res, next) => { req.id = uuidv4(); next(); });

// ── RATE LIMITING ──────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: 'Too many auth attempts, try again in 15 minutes.' },
});
const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: 'AI rate limit exceeded.' },
});

app.use('/api/', globalLimiter);
app.use('/api/auth/', authLimiter);
app.use('/api/ai/', aiLimiter);

// ── STATIC (serve frontend) ────────────────────────────────────
app.use(express.static(path.join(__dirname, '../frontend'), {
  maxAge: '1h',
  etag: true,
}));

// ── API ROUTES ─────────────────────────────────────────────────
app.use('/api/auth',     authRoutes);
app.use('/api/users',    userRoutes);
app.use('/api/messages', messageRoutes);
app.use('/api/media',    mediaRoutes);
app.use('/api/ai',       aiRoutes);
app.use('/api/keys',     keyRoutes);

// Health check
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    services: {
      websocket: 'active',
      database: 'connected',
      crypto: 'AES-256-GCM + Signal Protocol',
      ai: process.env.OLLAMA_URL || 'http://localhost:11434',
    },
  });
});

// SPA fallback
app.get('*', (_req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/index.html'));
});

// ── WEBSOCKET SIGNALING ────────────────────────────────────────
const signaling = new SignalingService(wss, verifyToken);

// ── ERROR HANDLERS ─────────────────────────────────────────────
app.use((err, req, res, _next) => {
  logger.error(`[${req.id}] ${err.message}`, { stack: err.stack });
  const status = err.status || err.statusCode || 500;
  res.status(status).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message,
    requestId: req.id,
  });
});

// ── START ──────────────────────────────────────────────────────
async function start() {
  await initDB();
  server.listen(PORT, () => {
    logger.info(`Kryonix backend running on port ${PORT}`);
    logger.info(`WebSocket signaling active at ws://localhost:${PORT}/ws`);
    logger.info(`Ollama AI gateway: ${process.env.OLLAMA_URL || 'http://localhost:11434'}`);
  });
}

start().catch(err => {
  logger.error('Startup failed:', err);
  process.exit(1);
});

module.exports = { app, server };
