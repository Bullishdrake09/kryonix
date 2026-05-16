# Kryonix Backend — Multi-stage Docker build
FROM node:20-alpine AS deps
WORKDIR /app
COPY backend/package*.json ./
RUN npm ci --only=production

FROM node:20-alpine AS runner
WORKDIR /app
RUN addgroup -g 1001 -S kryonix && adduser -S kryonix -u 1001
COPY --from=deps /app/node_modules ./node_modules
COPY backend/ ./backend/
COPY frontend/ ./frontend/
RUN mkdir -p logs && chown -R kryonix:kryonix /app
USER kryonix
EXPOSE 3001
ENV NODE_ENV=production
CMD ["node", "backend/server.js"]
