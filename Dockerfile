# ---- Build Stage ----
FROM oven/bun:1-alpine AS builder

ENV NODE_ENV="production"

# Set working directory
WORKDIR /app

# Copy package.json and lockfile first (better caching)
COPY package.json bun.lockb* ./

# Install deps
RUN bun install --omit=dev --frozen-lockfile

# Copy all project files
COPY . .

# Run your build script (creates /dist)
RUN bun run bun:build


# ---- Runtime Stage ----
FROM oven/bun:1-alpine

ENV NODE_ENV="production"

# Set working directory
WORKDIR /app

# Copy built dist files from builder
COPY --from=builder /app/dist ./dist

# Expose the port your Hono server runs on (default 3000?)
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

# Start the server with Bun
CMD ["bun", "./dist/index.js"]