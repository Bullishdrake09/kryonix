# Kryonix — Secure Chat Application

> **E2EE · WebRTC · On-Premise AI**  
> Signal Protocol · AES-256-GCM · DTLS-SRTP · Ollama

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                        KRYONIX STACK                           │
├─────────────────┬──────────────────┬───────────────────────────┤
│   Frontend      │    Backend       │    Services               │
│   (HTML/JS)     │  (Node/Express)  │                           │
│                 │                  │  ┌─────────────────────┐  │
│  Web Crypto API │  REST API        │  │  PostgreSQL / SQLite │  │
│  ECDH P-256     │  /api/auth       │  │  (ciphertext only)  │  │
│  AES-256-GCM    │  /api/messages   │  └─────────────────────┘  │
│  Signal Proto.  │  /api/ai         │                           │
│  IndexedDB      │  /api/media      │  ┌─────────────────────┐  │
│                 │  /api/keys       │  │  Ollama AI Gateway  │  │
│  WebRTC         │                  │  │  llama3.2, mistral… │  │
│  DTLS-SRTP      │  WebSocket       │  │  Zero data egress   │  │
│  SFU (group)    │  Signaling       │  └─────────────────────┘  │
│                 │  (SDP/ICE relay) │                           │
│                 │                  │  ┌─────────────────────┐  │
│                 │  Caddy TLS       │  │  coturn TURN server │  │
│                 │  Reverse Proxy   │  │  NAT traversal      │  │
│                 │                  │  └─────────────────────┘  │
└─────────────────┴──────────────────┴───────────────────────────┘
```

## Quick Start

### Option A — Frontend Only (Demo mode)
Open `frontend/index.html` directly in a browser. No backend required.  
All crypto runs in-browser. Ollama AI works if `ollama serve` is running locally.

### Option B — Full Stack (Development)

**Prerequisites:** Node.js ≥18, Git, (optional) Ollama

```bash
# 1. Clone / extract the project
cd kryonix

# 2. Run setup
bash scripts/setup.sh

# 3. Start Ollama AI (optional but recommended)
ollama serve &
ollama pull llama3.2:3b

# 4. Start backend
cd backend && npm run dev

# 5. Open browser
open http://localhost:3001
```

### Option C — Docker (Production)

```bash
# 1. Copy and fill environment
cp .env.example .env
# Edit .env with your secrets

# 2. Start all services
docker compose up -d

# 3. Pull AI model
docker exec kryonix-ollama ollama pull llama3.2:3b

# 4. Access at https://yourdomain.com
```

---

## Security Architecture

### End-to-End Encryption
| Layer | Technology |
|-------|-----------|
| Protocol | Signal Protocol (X3DH + Double Ratchet) |
| Key exchange | ECDH P-256 (Web Crypto API) |
| Session encryption | AES-256-GCM |
| Signing | Ed25519 |
| Group messaging | MLS (Messaging Layer Security) |
| Key storage | IndexedDB (wrapped with password-derived key) |
| Server storage | Public keys + ciphertext **only** |

### WebRTC Media Security
- All calls use **DTLS-SRTP** (RFC 5764) — media is encrypted peer-to-peer
- 1:1 calls: direct P2P WebRTC
- Group calls: SFU (Selective Forwarding Unit) — server forwards encrypted streams
- STUN: Google public STUN servers
- TURN: Self-hosted coturn with time-limited HMAC credentials

### AI Gateway Security
- Ollama runs **on-premise** — zero data egress to external AI services
- Input sanitization: strip prompt injection patterns before forwarding
- Output sanitization: strip HTML/JS from LLM responses
- Context limited to recent messages only (configurable window)
- Caddy handles TLS termination for Ollama endpoint

### Zero-Trust Model
- Server stores **no plaintext** — only ciphertext, IVs, and public keys
- JWT access tokens expire in 15 minutes
- Refresh tokens stored as SHA-256 hashes only
- Rate limiting on all endpoints
- Helmet.js CSP headers
- TURN credentials are time-limited (24h default)

---

## API Reference

### Authentication
```
POST /api/auth/register   — Register + upload key bundle
POST /api/auth/login      — Login, receive JWT
POST /api/auth/refresh    — Refresh access token
POST /api/auth/logout     — Invalidate session
```

### Messages (E2EE ciphertext only)
```
POST   /api/messages                  — Store encrypted message
GET    /api/messages/:conversationId  — Fetch ciphertexts
PUT    /api/messages/:id/read         — Mark as read
DELETE /api/messages/:id              — Delete
POST   /api/messages/:id/react        — Add/remove reaction
```

### Keys (X3DH / Signal Protocol)
```
POST /api/keys/bundle          — Upload key bundle after registration
GET  /api/keys/bundle/:userId  — Fetch prekey bundle for X3DH session init
POST /api/keys/prekeys         — Replenish one-time prekeys
GET  /api/keys/prekeys/count   — Check remaining OTPK count
```

### AI Gateway
```
GET  /api/ai/health    — Ollama health check
GET  /api/ai/models    — List available models
POST /api/ai/generate  — Generate (streaming SSE or batch)
POST /api/ai/chat      — Chat format (OpenAI-compatible)
```

### Media / WebRTC
```
GET  /api/media/turn-credentials  — HMAC TURN credentials
POST /api/media/calls             — Create call record
PUT  /api/media/calls/:id         — Update call status
GET  /api/media/calls             — Call history
```

### WebSocket Signaling (`ws://host/ws`)
```
auth             — Authenticate connection
message          — Relay encrypted message
typing/stop      — Typing indicators
call_offer       — WebRTC SDP offer
call_answer      — WebRTC SDP answer
call_reject      — Reject incoming call
ice_candidate    — ICE candidate exchange
key_update       — Signal key rotation
```

---

## File Structure

```
kryonix/
├── frontend/
│   └── index.html              # Full SPA (self-contained)
├── backend/
│   ├── server.js               # Express + WebSocket entry point
│   ├── package.json
│   ├── routes/
│   │   ├── auth.js             # Registration, login, token refresh
│   │   ├── users.js            # Profile, search, key fetch
│   │   ├── messages.js         # E2EE message storage/retrieval
│   │   ├── media.js            # TURN credentials, call records
│   │   ├── ai.js               # Ollama AI proxy (streaming)
│   │   └── keys.js             # X3DH prekey bundle management
│   ├── services/
│   │   ├── signaling.js        # WebSocket SDP/ICE relay
│   │   ├── jwt.js              # Token sign/verify
│   │   ├── logger.js           # Winston logger
│   │   └── ollama.js           # Ollama API client + sanitization
│   ├── crypto/
│   │   └── keyManager.js       # X3DH prekey distribution
│   ├── middleware/
│   │   ├── auth.js             # JWT guard
│   │   └── validate.js         # Joi input validation
│   └── db/
│       └── database.js         # Knex schema + migrations
├── scripts/
│   ├── setup.sh                # One-line setup
│   └── turnserver.conf         # coturn configuration
├── docs/
│   └── README.md
├── docker-compose.yml
├── Dockerfile
├── Caddyfile
├── .env.example
└── .gitignore
```

---

## Development Notes

- **Private keys never leave the browser** — Web Crypto API generates and stores them in IndexedDB
- **Server-side crypto** is limited to: JWT signing, bcrypt password hashing, TURN HMAC
- **Ollama must be running** for real AI responses; app falls back to simulation otherwise
- Run `ollama serve` then `ollama pull llama3.2:3b` before testing AI features
- WebRTC calls require HTTPS in production (or localhost for dev)
- SQLite is used for development; switch to PostgreSQL via `.env` for production
