/**
 * Kryonix — Ollama AI Gateway Service
 * Proxies requests to local Ollama instance
 * Sanitizes input/output to prevent prompt injection
 * All inference stays on-premise — zero data egress
 */
'use strict';

const { logger } = require('./logger');

const OLLAMA_URL     = process.env.OLLAMA_URL    || 'http://localhost:11434';
const OLLAMA_TIMEOUT = parseInt(process.env.OLLAMA_TIMEOUT) || 120000;

// ── SANITIZATION ──────────────────────────────────────────────
const INJECTION_PATTERNS = [
  /ignore\s+(previous|all|above|prior)\s+instructions?/gi,
  /system\s*:\s*/gi,
  /<\s*\/?\s*system\s*>/gi,
  /\[INST\]|\[\/INST\]/g,
  /<<SYS>>|<<\/SYS>>/g,
  /\bACT\s+AS\b/gi,
  /\bDAN\b/g,
  /jailbreak/gi,
];

function sanitizeInput(text) {
  if (typeof text !== 'string') return '';
  let s = text.slice(0, 4096); // length limit
  for (const p of INJECTION_PATTERNS) s = s.replace(p, '[filtered]');
  return s;
}

function sanitizeOutput(text) {
  if (typeof text !== 'string') return '';
  // Strip any HTML/script tags from LLM output before sending to client
  return text
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, '')
    .replace(/javascript:/gi, '')
    .trim();
}

// ── TAG-BASED CONTEXT ─────────────────────────────────────────
function buildPrompt(systemPrompt, contextMessages, userMessage) {
  const safeSystem  = sanitizeInput(systemPrompt);
  const safeUser    = sanitizeInput(userMessage);
  const ctxBlock    = contextMessages
    .slice(-10)
    .map(m => `${m.role === 'user' ? 'User' : 'Assistant'}: ${sanitizeInput(m.content)}`)
    .join('\n');
  return `${safeSystem}\n\n${ctxBlock ? 'Conversation:\n' + ctxBlock + '\n\n' : ''}User: ${safeUser}\nAssistant:`;
}

// ── API CALLS ────────────────────────────────────────────────
async function listModels() {
  const res = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`Ollama responded ${res.status}`);
  return res.json();
}

async function generate({ model, prompt, stream = false, options = {} }) {
  const body = JSON.stringify({ model, prompt, stream, options });
  const res  = await fetch(`${OLLAMA_URL}/api/generate`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    signal:  AbortSignal.timeout(OLLAMA_TIMEOUT),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Ollama error ${res.status}: ${err}`);
  }
  return res;
}

async function chat({ model, messages, stream = false, options = {} }) {
  const body = JSON.stringify({ model, messages, stream, options });
  const res  = await fetch(`${OLLAMA_URL}/api/chat`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body,
    signal:  AbortSignal.timeout(OLLAMA_TIMEOUT),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Ollama chat error ${res.status}: ${err}`);
  }
  return res;
}

async function healthCheck() {
  try {
    const res = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(3000) });
    if (!res.ok) return { ok: false, error: `HTTP ${res.status}` };
    const data = await res.json();
    return { ok: true, models: data.models?.length || 0, url: OLLAMA_URL };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

module.exports = {
  listModels, generate, chat, healthCheck,
  sanitizeInput, sanitizeOutput, buildPrompt,
  OLLAMA_URL,
};
