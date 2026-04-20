## ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
RUN npm run build

## ── Stage 2: Serve ──────────────────────────────────────────────────────────
FROM nginx:1.25-alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.sh /docker-entrypoint-ids.sh
RUN chmod +x /docker-entrypoint-ids.sh

EXPOSE 80 443
ENTRYPOINT ["/docker-entrypoint-ids.sh"]
