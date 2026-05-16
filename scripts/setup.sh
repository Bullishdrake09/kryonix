#!/usr/bin/env bash
# ═══════════════════════════════════════════════
# Kryonix — One-line setup script
# Usage: bash scripts/setup.sh
# ═══════════════════════════════════════════════
set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}"
echo "  ██╗  ██╗██████╗ ██╗   ██╗ ██████╗ ███╗   ██╗██╗██╗  ██╗"
echo "  ██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔═══██╗████╗  ██║██║╚██╗██╔╝"
echo "  █████╔╝ ██████╔╝ ╚████╔╝ ██║   ██║██╔██╗ ██║██║ ╚███╔╝ "
echo "  ██╔═██╗ ██╔══██╗  ╚██╔╝  ██║   ██║██║╚██╗██║██║ ██╔██╗ "
echo "  ██║  ██╗██║  ██║   ██║   ╚██████╔╝██║ ╚████║██║██╔╝ ██╗"
echo "  ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"
echo -e "${NC}"
echo -e "${GREEN}Secure Chat · E2EE · WebRTC · On-Premise AI${NC}"
echo ""

# Check Node.js
if ! command -v node &>/dev/null; then
  echo -e "${RED}Node.js not found. Install from https://nodejs.org (v18+)${NC}"; exit 1
fi
NODE_VER=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VER" -lt 18 ]; then
  echo -e "${RED}Node.js v18+ required (found $(node -v))${NC}"; exit 1
fi
echo -e "${GREEN}✓ Node.js $(node -v)${NC}"

# Install backend deps
echo -e "\n${CYAN}Installing backend dependencies…${NC}"
cd backend && npm install && cd ..
echo -e "${GREEN}✓ Backend dependencies installed${NC}"

# Create .env if not exists
if [ ! -f .env ]; then
  echo -e "\n${CYAN}Generating .env with random secrets…${NC}"
  cp .env.example .env
  # Generate random secrets
  ACCESS_SECRET=$(openssl rand -hex 64 2>/dev/null || node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
  REFRESH_SECRET=$(openssl rand -hex 64 2>/dev/null || node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
  TURN_SECRET=$(openssl rand -hex 32 2>/dev/null || node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
  sed -i.bak "s/CHANGE_ME_generate_with_openssl_rand_hex_64_ACCESS/$ACCESS_SECRET/g" .env 2>/dev/null || true
  # Use node to do substitution reliably cross-platform
  node -e "
    const fs = require('fs');
    let env = fs.readFileSync('.env','utf8');
    env = env.replace('CHANGE_ME_generate_with_openssl_rand_hex_64', '$ACCESS_SECRET');
    env = env.replace('CHANGE_ME_generate_with_openssl_rand_hex_64', '$REFRESH_SECRET');
    env = env.replace('CHANGE_ME_generate_with_openssl_rand_hex_32', '$TURN_SECRET');
    fs.writeFileSync('.env', env);
  "
  echo -e "${GREEN}✓ .env created with generated secrets${NC}"
else
  echo -e "${YELLOW}⚠  .env already exists, skipping${NC}"
fi

# Create logs directory
mkdir -p logs
echo -e "${GREEN}✓ Logs directory created${NC}"

# Check Ollama
echo ""
if command -v ollama &>/dev/null; then
  echo -e "${GREEN}✓ Ollama found: $(ollama --version 2>/dev/null || echo 'installed')${NC}"
  echo -e "${YELLOW}  Run 'ollama serve' and 'ollama pull llama3.2:3b' to activate AI${NC}"
else
  echo -e "${YELLOW}⚠  Ollama not found. Install from https://ollama.com${NC}"
  echo -e "${YELLOW}  Then run: ollama pull llama3.2:3b${NC}"
fi

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Kryonix is ready to start!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "  Start backend:  ${CYAN}cd backend && npm start${NC}"
echo -e "  Dev mode:       ${CYAN}cd backend && npm run dev${NC}"
echo -e "  Open browser:   ${CYAN}http://localhost:3001${NC}"
echo ""
echo -e "  Or open frontend/index.html directly in any browser (no backend needed for demo)"
echo ""
