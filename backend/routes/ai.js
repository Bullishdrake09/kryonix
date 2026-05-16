/**
 * Kryonix — AI Gateway Routes
 * Proxies to local Ollama with input/output sanitization
 * Streaming SSE and non-streaming endpoints
 */
'use strict';

const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { validate, schemas } = require('../middleware/validate');
const {
  listModels, generate, chat, healthCheck,
  sanitizeInput, sanitizeOutput, buildPrompt,
} = require('../services/ollama');
const { logger } = require('../services/logger');
const router = express.Router();

router.use(requireAuth);

// GET /api/ai/health
router.get('/health', async (_req, res) => {
  const status = await healthCheck();
  res.json(status);
});

// GET /api/ai/models
router.get('/models', async (_req, res) => {
  try {
    const data = await listModels();
    res.json(data);
  } catch (err) {
    res.status(503).json({ error: 'Ollama unavailable: ' + err.message });
  }
});

// POST /api/ai/generate — streaming or non-streaming
router.post('/generate', validate(schemas.aiGenerate), async (req, res) => {
  const { model, prompt, systemPrompt, stream, contextMessages, options } = req.body;

  const fullPrompt = buildPrompt(
    systemPrompt || 'You are a helpful, concise AI assistant in Kryonix, a secure chat app.',
    contextMessages,
    prompt
  );

  logger.info(`AI generate: user=${req.user.userId} model=${model} stream=${stream}`);

  try {
    if (stream) {
      // SSE streaming response
      res.setHeader('Content-Type',  'text/event-stream');
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection',    'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');

      const ollamaRes = await generate({ model, prompt: fullPrompt, stream: true, options });
      const reader    = ollamaRes.body.getReader();
      const decoder   = new TextDecoder();

      req.on('close', () => reader.cancel());

      while (true) {
        const { done, value } = await reader.read();
        if (done) { res.write('data: [DONE]\n\n'); res.end(); break; }
        const chunk = decoder.decode(value, { stream: true });
        for (const line of chunk.split('\n').filter(Boolean)) {
          try {
            const j = JSON.parse(line);
            if (j.response) {
              const safe = sanitizeOutput(j.response);
              res.write(`data: ${JSON.stringify({ token: safe, done: j.done })}\n\n`);
            }
            if (j.done) { res.write('data: [DONE]\n\n'); res.end(); return; }
          } catch {}
        }
      }
    } else {
      const ollamaRes = await generate({ model, prompt: fullPrompt, stream: false, options });
      const data      = await ollamaRes.json();
      res.json({ response: sanitizeOutput(data.response), model, done: true });
    }
  } catch (err) {
    logger.error('AI generate error:', err.message);
    if (!res.headersSent) {
      res.status(503).json({ error: 'AI gateway error: ' + err.message });
    }
  }
});

// POST /api/ai/chat — OpenAI-compatible chat format
router.post('/chat', requireAuth, async (req, res) => {
  const { model = 'llama3.2:3b', messages = [], stream = false, options = {} } = req.body;
  if (!messages.length) return res.status(400).json({ error: 'messages array required' });

  const sanitized = messages.map(m => ({
    role:    m.role,
    content: sanitizeInput(m.content),
  }));

  try {
    const ollamaRes = await chat({ model, messages: sanitized, stream, options });
    if (stream) {
      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control','no-cache');
      const reader  = ollamaRes.body.getReader();
      const decoder = new TextDecoder();
      req.on('close', () => reader.cancel());
      while (true) {
        const { done, value } = await reader.read();
        if (done) { res.write('data: [DONE]\n\n'); res.end(); break; }
        const chunk = decoder.decode(value, { stream: true });
        for (const line of chunk.split('\n').filter(Boolean)) {
          try {
            const j = JSON.parse(line);
            const token = j.message?.content;
            if (token) res.write(`data: ${JSON.stringify({ token: sanitizeOutput(token), done: j.done })}\n\n`);
            if (j.done) { res.write('data: [DONE]\n\n'); res.end(); return; }
          } catch {}
        }
      }
    } else {
      const data = await ollamaRes.json();
      res.json({ response: sanitizeOutput(data.message?.content || ''), model, done: true });
    }
  } catch (err) {
    logger.error('AI chat error:', err.message);
    if (!res.headersSent) res.status(503).json({ error: err.message });
  }
});

module.exports = router;
