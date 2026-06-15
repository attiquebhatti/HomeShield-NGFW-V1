# HomeShield NGFW — management server (UI + API)
# Multi-stage: build the React UI, then a slim runtime with prod deps only.

FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Server entrypoint + its pure ESM modules and the SQL schema.
COPY server.js feeds.mjs wireguard.mjs backup.mjs totp.mjs metrics.mjs ipsec.mjs bootstrap.mjs google.mjs appsignatures.mjs ./
COPY api ./api
# Windows agent script is served as a download by the console.
COPY agent-windows ./agent-windows
COPY --from=build /app/dist ./dist

EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1

CMD ["node", "server.js"]
