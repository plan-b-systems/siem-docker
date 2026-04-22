FROM node:22-alpine AS builder

WORKDIR /app

# Build tools required for better-sqlite3 native compile
RUN apk add --no-cache python3 make g++

COPY package.json package-lock.json* ./
RUN npm install

COPY . .
RUN npm run build

# Production image
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

# Copy standalone build. Next's standalone output includes any node_modules
# required at runtime — including better-sqlite3's compiled .node binary.
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public

# Emergency admin-reset CLI (run via 'docker exec plan-b-dashboard node scripts/reset-admin.js').
COPY --from=builder /app/scripts ./scripts

EXPOSE 3000

CMD ["node", "server.js"]
